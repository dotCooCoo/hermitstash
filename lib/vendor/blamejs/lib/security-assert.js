// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * security-assert — boot-time policy assertions for production posture.
 *
 * The framework already prints WARNINGs when individual security
 * choices land in their dev-friendly defaults (vault plaintext mode,
 * db at-rest plain, audit-sign plaintext, NTP drift, etc.). Operators
 * shipping a real deployment want a stricter gate: not "warn, then
 * boot anyway" but "this combination of settings is not acceptable
 * in production — fail boot so we don't silently ship a weak posture
 * to prod."
 *
 * b.security.assertProduction({ ... }) is the policy engine. It
 * collects the operator's stated production-mode requirements and
 * either passes silently OR throws a SecurityAssertError listing
 * every failed assertion so the operator gets the full diagnostic on
 * the first restart.
 *
 *   await b.security.assertProduction({
 *     // Required posture (default true — set false to opt out per-line)
 *     vault:           "wrapped",         // require b.vault.getMode() === this
 *     dbAtRest:        "encrypted",       // require b.db.getAtRestMode() === this
 *     auditSigning:    "wrapped",         // require b.auditSign.getMode() === this
 *     ntpStrict:       true,              // require BLAMEJS_NTP_STRICT != "0"
 *
 *     // Each of these is an opt-in tightening. Default off — the
 *     // framework doesn't know which are appropriate to YOUR deploy.
 *     requireTLS:      true,              // refuse boot if app.protocol !== 'https'
 *                                         //   (no app.protocol on cleartext deployments)
 *     requireCSPNonce: true,              // require operator wired b.middleware.cspNonce
 *     requireCSRF:     true,              // require b.middleware.csrfProtect mounted
 *     requireRateLimit:true,              // require b.middleware.rateLimit mounted
 *
 *     // Operator-supplied custom assertions. Each is a function returning
 *     // { ok: bool, code, message }. Failed asserts are aggregated into
 *     // the thrown error.
 *     extra: [
 *       function () {
 *         return { ok: !!process.env.WIKI_ADMIN_PASSWORD,
 *           code: "wiki/admin-password-missing",
 *           message: "WIKI_ADMIN_PASSWORD must be set in production" };
 *       },
 *     ],
 *
 *     // Wire the audit so the operator's audit chain captures both
 *     // pass AND fail outcomes (next operator can see "boot was asserted
 *     // production-clean at <T>" or "asserts failed at <T> with reasons").
 *     audit: b.audit,
 *
 *     // The detected indicators the policy reads. Optional; default
 *     // resolves from the framework instance via lazy-require so the
 *     // call site stays minimal.
 *     resolvers: {
 *       vault:        function () { return require("./vault").getMode(); },
 *       dbAtRest:     function () { return require("./db").getAtRestMode(); },
 *       auditSigning: function () { return require("./audit-sign").getMode(); },
 *     },
 *   });
 *   // throws SecurityAssertError on any failure;
 *   //   each failure carries { code, message } and the .failures array
 *   //   on the error lists them all
 *
 * The audit event namespace is "system.security.assert" — pass / fail
 * lands on the chain like every other framework lifecycle event.
 *
 * Validation: throws at config time on malformed opts (unknown key,
 * non-function extra entry, etc.) so the operator catches typos at
 * boot, not at the moment they were trying to gate the boot.
 */
var nodeFs = require("node:fs");
var nodeTls = require("node:tls");
var lazyRequire = require("./lazy-require");
var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

// Default minimum Node major version — pinned to the framework's
// supported LTS line (operator can override at their own risk).
var DEFAULT_MIN_NODE_MAJOR = 0x18;
// Octal radix for fs-mode formatting (chmod-style 0o755 / 0o750 output).
var OCTAL_RADIX = 0x8;

var audit = lazyRequire(function () { return require("./audit"); });
var vault = lazyRequire(function () { return require("./vault"); });
var db = lazyRequire(function () { return require("./db"); });
var auditSign = lazyRequire(function () { return require("./audit-sign"); });
var networkTls   = lazyRequire(function () { return require("./network-tls"); });
var networkProxy = lazyRequire(function () { return require("./network-proxy"); });

var SecurityAssertError = defineClass("SecurityAssertError", { alwaysPermanent: true });

var DEFAULT_RESOLVERS = Object.freeze({
  vault:        function () {
    try { return vault().getMode(); } catch (_e) { return null; }
  },
  dbAtRest:     function () {
    try {
      var d = db();
      return typeof d.getAtRestMode === "function" ? d.getAtRestMode() : null;
    } catch (_e) { return null; }
  },
  auditSigning: function () {
    try { return auditSign().getMode(); } catch (_e) { return null; }
  },
});

function _check(name, want, gotter) {
  var got;
  try { got = gotter(); }
  catch (e) {
    return { ok: false, code: "security/" + name + "-resolver-failed",
      message: name + " resolver threw: " + ((e && e.message) || String(e)) };
  }
  if (got !== want) {
    return { ok: false, code: "security/" + name + "-mismatch",
      message: name + " is '" + got + "', production policy requires '" + want + "'" };
  }
  return { ok: true };
}

async function assertProduction(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "vault", "dbAtRest", "auditSigning", "ntpStrict",
    "requireTLS", "requireCSPNonce", "requireCSRF", "requireRateLimit",
    "extra", "audit", "resolvers", "router", "protocol",
    "minNodeMajor", "minTlsVersion", "requireEnv", "forbidEnv",
    "dataDir", "maxDataDirMode", "forbidNodeEnv",
    "allowDpiTrust", "forbidProxy",
  ], "security.assertProduction");

  var resolvers = Object.assign({}, DEFAULT_RESOLVERS, opts.resolvers || {});
  var failures = [];

  // Each posture-mode default fires unless the operator explicitly
  // sets it to false. The default value is the production-target
  // string for that posture.
  function _maybeRun(name, want, gotter) {
    if (want === false || want === null || want === undefined) return;
    var verdict = _check(name, want, gotter);
    if (!verdict.ok) failures.push(verdict);
  }
  _maybeRun("vault",        opts.vault        !== undefined ? opts.vault        : "wrapped",   resolvers.vault);
  _maybeRun("dbAtRest",     opts.dbAtRest     !== undefined ? opts.dbAtRest     : "encrypted", resolvers.dbAtRest);
  _maybeRun("auditSigning", opts.auditSigning !== undefined ? opts.auditSigning : "wrapped",   resolvers.auditSigning);

  // ntpStrict default ON — production should refuse to boot on >1hr
  // clock drift (audit-chain timestamps stop being trustworthy).
  if (opts.ntpStrict !== false) {
    var ntpEnv = safeEnv.readVar("BLAMEJS_NTP_STRICT");
    if (ntpEnv === "0" || ntpEnv === "false") {
      failures.push({ ok: false, code: "security/ntp-strict-disabled",
        message: "BLAMEJS_NTP_STRICT is '" + ntpEnv + "'; production policy requires NTP strict mode" });
    }
  }

  // Optional opt-in tightenings. Operators set these true when their
  // deployment shape satisfies the requirement.
  if (opts.requireTLS === true) {
    var protocol = opts.protocol || "";   // operator-supplied (no framework signal — TLS may terminate at the proxy)
    if (protocol !== "https") {
      failures.push({ ok: false, code: "security/tls-required",
        message: "requireTLS:true but observed protocol is '" + protocol + "'; pass opts.protocol from your TLS terminator config" });
    }
  }
  if (opts.requireCSPNonce === true || opts.requireCSRF === true || opts.requireRateLimit === true) {
    if (!opts.router || !Array.isArray(opts.router._mounted)) {
      failures.push({ ok: false, code: "security/router-introspection-missing",
        message: "require* middleware checks need opts.router exposing ._mounted (the router's mounted middleware list); pass the framework Router instance" });
    } else {
      var mounted = opts.router._mounted.map(function (m) { return (m.name || "").toLowerCase(); });
      function _requireMounted(name, label) {
        if (mounted.indexOf(name) === -1) {
          failures.push({ ok: false, code: "security/middleware-missing",
            message: label + " is not mounted on the router; production policy requires it" });
        }
      }
      if (opts.requireCSPNonce  === true) _requireMounted("cspnonce",     "b.middleware.cspNonce");
      if (opts.requireCSRF      === true) _requireMounted("csrfprotect",  "b.middleware.csrfProtect");
      if (opts.requireRateLimit === true) _requireMounted("ratelimit",    "b.middleware.rateLimit");
    }
  }

  // Node major version. Defaults to the framework's pinned LTS;
  // operator can pin lower at their own risk.
  var minNodeMajor = opts.minNodeMajor !== undefined ? opts.minNodeMajor : DEFAULT_MIN_NODE_MAJOR;
  if (minNodeMajor !== false && typeof minNodeMajor === "number") {
    var nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
    if (nodeMajor < minNodeMajor) {
      failures.push({ ok: false, code: "security/node-version",
        message: "Node " + process.versions.node + " < required minimum major " + minNodeMajor +
          " — upgrade Node before deploying" });
    }
  }

  // TLS minimum version. Production should be TLS 1.3-only; the
  // framework's pqcGate already enforces that for inbound HTTPS but
  // operators with their own server.listen() flow should re-assert.
  if (opts.minTlsVersion !== undefined && opts.minTlsVersion !== false) {
    if (nodeTls && nodeTls.DEFAULT_MIN_VERSION) {
      var got = nodeTls.DEFAULT_MIN_VERSION;
      var want = opts.minTlsVersion;
      // Compare TLSv1.3 > TLSv1.2 > TLSv1.1 > TLSv1.0 by string.
      var order = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
      // Validate BOTH the operator-supplied required version AND the
      // currently-active version against the known-vocabulary BEFORE
      // the rank compare. A typo'd `want` (e.g. "TLS1.3" or "TLSv1.4")
      // maps to indexOf === -1; without this check, the comparison
      // `3 < -1 === false` silently passes even though the operator
      // asked for a version the framework doesn't recognize.
      // Throw at config time — this is a production-posture entry
      // point and operator typos must be loud at boot, not deferred
      // to per-request audit.
      if (order.indexOf(want) === -1) {
        throw new TypeError(
          "assertProductionPosture: opts.minTlsVersion '" + want +
          "' is not one of " + order.join(" / "));
      }
      if (order.indexOf(got) === -1) {
        // Node's DEFAULT_MIN_VERSION shouldn't ever drift outside the
        // canonical 4-value vocabulary, but if it does (future Node
        // version, monkey-patched runtime), surface the failure
        // rather than silently treating it as "below required".
        failures.push({ ok: false, code: "security/tls-min-version",
          message: "Node TLS DEFAULT_MIN_VERSION is an unrecognized value '" + got +
            "' (expected one of " + order.join(" / ") + "); required '" + want + "'" });
      } else if (order.indexOf(got) < order.indexOf(want)) {
        failures.push({ ok: false, code: "security/tls-min-version",
          message: "Node TLS DEFAULT_MIN_VERSION is '" + got + "', required '" + want + "'" });
      }
    }
  }

  // Required env-var presence. Common pattern: BLAMEJS_VAULT_PASSPHRASE
  // MUST be set when vault is in wrapped mode. Operator-supplied list
  // because the requirements are deployment-specific.
  if (Array.isArray(opts.requireEnv)) {
    for (var ri = 0; ri < opts.requireEnv.length; ri++) {
      var reKey = opts.requireEnv[ri];
      if (typeof reKey !== "string" || reKey.length === 0) continue;
      var reVal = safeEnv.readVar(reKey);
      if (!reVal || reVal.length === 0) {
        failures.push({ ok: false, code: "security/env-missing",
          message: "production policy requires env var '" + reKey + "' to be set and non-empty" });
      }
    }
  }

  // Forbidden env-var presence. Catches dev / debug knobs that
  // shouldn't reach production (BLAMEJS_DEBUG, BLAMEJS_NTP_STRICT=0
  // when ntpStrict is on, etc.).
  if (Array.isArray(opts.forbidEnv)) {
    for (var fi = 0; fi < opts.forbidEnv.length; fi++) {
      var feEntry = opts.forbidEnv[fi];
      if (typeof feEntry === "string") {
        if (safeEnv.readVar(feEntry) !== undefined) {
          failures.push({ ok: false, code: "security/env-forbidden",
            message: "production policy forbids env var '" + feEntry + "' but it is set" });
        }
      } else if (feEntry && typeof feEntry === "object" && typeof feEntry.key === "string") {
        // Forbid only when value matches.
        if (safeEnv.readVar(feEntry.key) === feEntry.value) {
          failures.push({ ok: false, code: "security/env-forbidden-value",
            message: "production policy forbids env var '" + feEntry.key +
              "' = '" + feEntry.value + "' but the runtime has exactly that" });
        }
      }
    }
  }

  // NODE_ENV pinning — refuses common-mistake values like
  // "development" or "test" in a production-asserted boot.
  if (opts.forbidNodeEnv !== false) {
    var forbidNodeEnv = Array.isArray(opts.forbidNodeEnv) ? opts.forbidNodeEnv : ["development", "dev", "test"];
    var nodeEnvVal = safeEnv.readVar("NODE_ENV");
    if (nodeEnvVal && forbidNodeEnv.indexOf(nodeEnvVal) !== -1) {
      failures.push({ ok: false, code: "security/node-env-forbidden",
        message: "NODE_ENV='" + nodeEnvVal + "' is in the production-forbidden list " +
          JSON.stringify(forbidNodeEnv) });
    }
  }

  // dataDir mode check — refuses world-writable / group-writable
  // data directories (mode > 0o750 by default). POSIX-only; Windows
  // skips silently.
  if (typeof opts.dataDir === "string" && opts.dataDir.length > 0 && process.platform !== "win32") {
    var maxMode = typeof opts.maxDataDirMode === "number" ? opts.maxDataDirMode : 0o750;
    try {
      var stat = nodeFs.statSync(opts.dataDir);
      var mode = stat.mode & 0o777;
      if (mode > maxMode) {
        failures.push({ ok: false, code: "security/datadir-permissions",
          message: "dataDir '" + opts.dataDir + "' has mode 0" + mode.toString(OCTAL_RADIX) +
            "; production policy requires <= 0" + maxMode.toString(OCTAL_RADIX) +
            " (chmod " + maxMode.toString(OCTAL_RADIX) + " " + opts.dataDir + ")" });
      }
    } catch (e) {
      failures.push({ ok: false, code: "security/datadir-stat-failed",
        message: "dataDir '" + opts.dataDir + "' could not be stat'd: " +
          ((e && e.message) || String(e)) });
    }
  }

  // CORS allow-all detection — the most common production-mistake
  // middleware misconfig. Catches a router whose CORS middleware
  // origins config is the literal "*" wildcard.
  if (opts.router && Array.isArray(opts.router._mounted)) {
    var corsMounted = opts.router._mounted.find(function (m) {
      return (m.name || "").toLowerCase() === "cors";
    });
    if (corsMounted && corsMounted.opts && corsMounted.opts.origins === "*") {
      failures.push({ ok: false, code: "security/cors-allow-all",
        message: "b.middleware.cors is mounted with origins:'*' — production policy forbids wildcard CORS" });
    }
  }

  if (opts.allowDpiTrust !== true) {
    var trustList = null;
    try { trustList = networkTls().getTrustStore(); } catch (_e) { trustList = null; }
    if (trustList && trustList.length > 0) {
      failures.push({ ok: false, code: "security/dpi-trust-installed",
        message: "network.tls trust store has " + trustList.length +
          " operator-installed CA(s); production policy refuses runtime trust additions unless allowDpiTrust:true is set" });
    }
  }

  if (opts.forbidProxy === true) {
    var proxySnap = null;
    try { proxySnap = networkProxy().snapshot(); } catch (_e) { proxySnap = null; }
    if (proxySnap && (proxySnap.http || proxySnap.https)) {
      failures.push({ ok: false, code: "security/outbound-proxy-set",
        message: "network.proxy is configured (http=" + !!proxySnap.http +
          ", https=" + !!proxySnap.https + "); production policy with forbidProxy:true refuses outbound proxy" });
    }
  }

  // Operator-supplied extra asserts.
  if (opts.extra !== undefined) {
    if (!Array.isArray(opts.extra)) {
      throw new SecurityAssertError(
        "BAD_OPT",
        "security.assertProduction: opts.extra must be an array of functions, got " + typeof opts.extra);
    }
    for (var ei = 0; ei < opts.extra.length; ei++) {
      if (typeof opts.extra[ei] !== "function") {
        throw new SecurityAssertError(
          "BAD_OPT",
          "security.assertProduction: opts.extra[" + ei + "] must be a function");
      }
      var verdict;
      try { verdict = await opts.extra[ei](); }
      catch (e) {
        verdict = { ok: false, code: "security/extra-threw",
          message: "extra[" + ei + "] threw: " + ((e && e.message) || String(e)) };
      }
      if (!verdict || verdict.ok !== true) {
        failures.push(Object.assign({ ok: false, code: "security/extra-failed",
          message: "extra[" + ei + "] returned not-ok" }, verdict || {}));
      }
    }
  }

  // Audit pass / fail to the chain regardless of outcome — operators
  // need both signals (production-clean boots are evidence too).
  var auditOn = opts.audit !== false && opts.audit != null;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;
  if (auditOn) {
    var sink = auditInstance || audit();
    try {
      sink.safeEmit({
        action:   failures.length === 0 ? "system.security.assert.success" : "system.security.assert.failure",
        outcome:  failures.length === 0 ? "success" : "failure",
        metadata: {
          failureCount: failures.length,
          failedCodes:  failures.map(function (f) { return f.code; }),
        },
      });
    } catch (_e) { /* audit best-effort */ }
  }

  if (failures.length > 0) {
    var summary = failures.map(function (f) { return "  - " + f.code + ": " + f.message; }).join("\n");
    var err = new SecurityAssertError(
      "ASSERT_FAILED",
      "production security policy failed (" + failures.length + " assertion(s)):\n" + summary);
    err.failures = failures;
    throw err;
  }
}

module.exports = {
  assertProduction:     assertProduction,
  SecurityAssertError:  SecurityAssertError,
  DEFAULT_RESOLVERS:    DEFAULT_RESOLVERS,
};
