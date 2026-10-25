// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.security
 * @nav    Production
 * @title  Security Assert
 * @slug   security
 *
 * @intro
 *   A boot-time assertion that the posture a deployment believes it has is
 *   the posture it actually has. It reads the live modes rather than the
 *   configuration meant to produce them, so a vault that fell back to
 *   plaintext, a database that opened unencrypted or an audit chain that is
 *   not signing is caught before the process serves a request.
 *
 *   Every check is a policy the operator states and the framework verifies:
 *   the vault, database and audit-signing modes, NTP strictness, TLS and its
 *   minimum version, the CSP nonce, CSRF and rate-limit middleware, the Node
 *   major version, required and forbidden environment variables, the data
 *   directory's mode, and whether a DPI-terminating proxy is tolerated.
 *   Checks opt out individually, so a deployment that cannot meet one says so
 *   in the call rather than skipping the assertion.
 *
 *   It raises once with every failure rather than on the first, and each
 *   failure carries a code, so an operator fixes the whole list in one pass.
 *
 *   Nothing is written to the audit chain unless the call asks for it. Pass
 *   <code>audit: true</code> to use the framework chain, or an audit sink of
 *   your own, and the verdict is recorded whether it passed or failed. Left
 *   out, the assertion raises or returns and no record of it exists, so a
 *   deployment that needs "we asserted our posture at boot" to be an
 *   auditable claim has to turn it on.
 *
 * @card
 *   Assert at boot that the live vault, database, audit-signing, TLS and
 *   middleware posture matches the policy a deployment states, raising once
 *   with every failure, and recording the verdict in the audit chain when
 *   asked to.
 */

var nodeFs = require("node:fs");
var nodeTls = require("node:tls");
var lazyRequire = require("./lazy-require");
var safeEnv = require("./parsers/safe-env");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DEFAULT_MIN_NODE_MAJOR = 0x18;
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

/**
 * @primitive b.security.assertProduction
 * @signature b.security.assertProduction(opts?)
 * @since     0.6.14
 * @status    stable
 * @related   b.vault.init, b.auditSign.init, b.ntpCheck.bootCheck
 *
 * Verify the deployment's security posture and resolve when it holds. Each
 * check reads the live value through a resolver rather than the config, so
 * what is asserted is the state the process is actually in.
 *
 * Seven checks run without being asked for, and each opts out individually.
 * Three assert a mode: the vault is `wrapped`, the database is `encrypted` at
 * rest, and audit signing is `wrapped`. Passing a different string asserts
 * that value instead; `false` or `null` skips the check.
 *
 * The other four are the production floor. `ntpStrict` fails when
 * `BLAMEJS_NTP_STRICT` is `0` or `false`, unless `ntpStrict: false`.
 * `minNodeMajor` defaults to 24. `forbidNodeEnv` defaults to rejecting
 * `development`, `dev` and `test`, so a production assertion fails on a
 * deployment still carrying a development `NODE_ENV`. An installed
 * DPI-terminating trust anchor fails unless `allowDpiTrust: true`.
 *
 * Everything else runs only when asked for.
 *
 * Every failure is collected, so one call reports the whole list. It raises
 * `security-assert/assert-failed` with one line per failure, and `failures` on
 * the error carries the code and message of each. A boolean option given a
 * non-boolean raises `security-assert/bad-opt`, because a typo there used to
 * skip the check silently.
 *
 * The outcome is emitted as `system.security.assert.success` or
 * `system.security.assert.failure` with the failed codes, unless `audit` is
 * `false` or absent. Pass an audit instance to record it somewhere other than
 * the framework's own chain.
 *
 * @opts
 *   vault:            string,   // default "wrapped"; false skips
 *   dbAtRest:         string,   // default "encrypted"; false skips
 *   auditSigning:     string,   // default "wrapped"; false skips
 *   ntpStrict:        boolean,  // default on; false skips the check
 *   minNodeMajor:     number,   // default 24
 *   forbidNodeEnv:    array,    // default ["development", "dev", "test"]
 *   allowDpiTrust:    boolean,  // default false; an installed anchor fails
 *   requireTLS:       boolean,
 *   minTlsVersion:    string,   // e.g. "TLSv1.3"
 *   requireCSPNonce:  boolean,
 *   requireCSRF:      boolean,
 *   requireRateLimit: boolean,
 *   router:           object,   // the router the middleware checks read
 *   protocol:         string,
 *   requireEnv:       array,    // variable names that must be set
 *   forbidEnv:        array,    // variable names that must not be set
 *   dataDir:          string,   // checked against maxDataDirMode
 *   maxDataDirMode:   number,   // octal mode ceiling
 *   forbidProxy:      boolean,
 *   extra:            array,    // functions returning a verdict
 *   resolvers:        object,   // override how a live value is read
 *   audit:            object,   // audit instance, or false to stay silent
 *
 * @example
 *   var b = require("@blamejs/core");
 *   try {
 *     await b.security.assertProduction({
 *       requireTLS:    true,
 *       minTlsVersion: "TLSv1.3",
 *       requireCSRF:   true,
 *       forbidEnv:     ["BLAMEJS_ALLOW_PLAINTEXT_VAULT"],
 *     });
 *   } catch (e) {
 *     e.code;                              // → "security-assert/assert-failed"
 *     e.failures.map(function (f) { return f.code; });
 *   }
 */
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
  ["requireTLS", "requireCSPNonce", "requireCSRF", "requireRateLimit",
   "forbidProxy", "ntpStrict", "allowDpiTrust"].forEach(function (name) {
    validateOpts.optionalBoolean(opts[name],
      "security.assertProduction: opts." + name + " (whether that check runs; anything " +
      "other than a boolean skipped it silently)",
      SecurityAssertError, "security-assert/bad-opt");
  });

  var resolvers = Object.assign({}, DEFAULT_RESOLVERS, opts.resolvers || {});
  var failures = [];

  function _maybeRun(name, want, gotter) {
    if (want === false || want === null || want === undefined) return;
    var verdict = _check(name, want, gotter);
    if (!verdict.ok) failures.push(verdict);
  }
  _maybeRun("vault",        opts.vault        !== undefined ? opts.vault        : "wrapped",   resolvers.vault);
  _maybeRun("dbAtRest",     opts.dbAtRest     !== undefined ? opts.dbAtRest     : "encrypted", resolvers.dbAtRest);
  _maybeRun("auditSigning", opts.auditSigning !== undefined ? opts.auditSigning : "wrapped",   resolvers.auditSigning);

  if (opts.ntpStrict !== false) {
    var ntpEnv = safeEnv.readVar("BLAMEJS_NTP_STRICT");
    if (ntpEnv === "0" || ntpEnv === "false") {
      failures.push({ ok: false, code: "security/ntp-strict-disabled",
        message: "BLAMEJS_NTP_STRICT is '" + ntpEnv + "'; production policy requires NTP strict mode" });
    }
  }

  if (opts.requireTLS === true) {
    var protocol = opts.protocol || "";
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

  var minNodeMajor = opts.minNodeMajor !== undefined ? opts.minNodeMajor : DEFAULT_MIN_NODE_MAJOR;
  if (minNodeMajor !== false && typeof minNodeMajor === "number") {
    var nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
    if (nodeMajor < minNodeMajor) {
      failures.push({ ok: false, code: "security/node-version",
        message: "Node " + process.versions.node + " < required minimum major " + minNodeMajor +
          " — upgrade Node before deploying" });
    }
  }

  if (opts.minTlsVersion !== undefined && opts.minTlsVersion !== false) {
    if (nodeTls && nodeTls.DEFAULT_MIN_VERSION) {
      var got = nodeTls.DEFAULT_MIN_VERSION;
      var want = opts.minTlsVersion;
      var order = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
      if (order.indexOf(want) === -1) {
        throw new TypeError(
          "assertProductionPosture: opts.minTlsVersion '" + want +
          "' is not one of " + order.join(" / "));
      }
      if (order.indexOf(got) === -1) {
        failures.push({ ok: false, code: "security/tls-min-version",
          message: "Node TLS DEFAULT_MIN_VERSION is an unrecognized value '" + got +
            "' (expected one of " + order.join(" / ") + "); required '" + want + "'" });
      } else if (order.indexOf(got) < order.indexOf(want)) {
        failures.push({ ok: false, code: "security/tls-min-version",
          message: "Node TLS DEFAULT_MIN_VERSION is '" + got + "', required '" + want + "'" });
      }
    }
  }

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

  if (Array.isArray(opts.forbidEnv)) {
    for (var fi = 0; fi < opts.forbidEnv.length; fi++) {
      var feEntry = opts.forbidEnv[fi];
      if (typeof feEntry === "string") {
        if (safeEnv.readVar(feEntry) !== undefined) {
          failures.push({ ok: false, code: "security/env-forbidden",
            message: "production policy forbids env var '" + feEntry + "' but it is set" });
        }
      } else if (feEntry && typeof feEntry === "object" && typeof feEntry.key === "string") {
        if (safeEnv.readVar(feEntry.key) === feEntry.value) {
          failures.push({ ok: false, code: "security/env-forbidden-value",
            message: "production policy forbids env var '" + feEntry.key +
              "' = '" + feEntry.value + "' but the runtime has exactly that" });
        }
      }
    }
  }

  if (opts.forbidNodeEnv !== false) {
    var forbidNodeEnv = Array.isArray(opts.forbidNodeEnv) ? opts.forbidNodeEnv : ["development", "dev", "test"];
    var nodeEnvVal = safeEnv.readVar("NODE_ENV");
    if (nodeEnvVal && forbidNodeEnv.indexOf(nodeEnvVal) !== -1) {
      failures.push({ ok: false, code: "security/node-env-forbidden",
        message: "NODE_ENV='" + nodeEnvVal + "' is in the production-forbidden list " +
          JSON.stringify(forbidNodeEnv) });
    }
  }

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

  if (opts.extra !== undefined) {
    if (!Array.isArray(opts.extra)) {
      throw new SecurityAssertError(
        "security-assert/bad-opt",
        "security.assertProduction: opts.extra must be an array of functions, got " + typeof opts.extra);
    }
    for (var ei = 0; ei < opts.extra.length; ei++) {
      if (typeof opts.extra[ei] !== "function") {
        throw new SecurityAssertError(
          "security-assert/bad-opt",
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
      "security-assert/assert-failed",
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
