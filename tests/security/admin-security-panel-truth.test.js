"use strict";

/**
 * The security panel must not report a protection the server is not applying.
 *
 * Admin → Security is what an operator reads to decide whether a deployment is
 * safe to expose. Two of its rows were computed from predicates the server does
 * not use:
 *
 *   TLS / HTTPS said "enabled" whenever a private key was on disk. The server
 *   opens a TLS listener only when the certificate is there too, and otherwise
 *   logs that it is starting in HTTP mode — so a key mounted ahead of its chain,
 *   or a renewal that replaced one and not the other, produced a green row on an
 *   install serving plain HTTP.
 *
 *   mTLS enforcement said "hard (TLS layer)" whenever ENFORCE_MTLS_STRICT was
 *   true and a CA existed. Hard enforcement is rejectUnauthorized on the TLS
 *   listener, so with no listener nothing requires a client certificate at all —
 *   and ENFORCE_MTLS_STRICT does not switch the app-layer check on in its place.
 *
 * Both told the operator a gate was closed while it was open, which is worse
 * than reporting nothing.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var testEnv = require("../helpers/test-env");
var tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "hs-panel-"));
process.env.HERMITSTASH_DATA_DIR = tmpDataDir;

var vault = require("../../lib/vault");

before(async function () { await vault.init(); });
after(function () {
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

var projectRoot = path.join(__dirname, "..", "..");

// The two predicates, read out of the source. Driving the real endpoint would
// need an admin session, a listening server and control over the process
// environment at boot; what is worth pinning is that the panel's inputs match
// the server's, and that is a property of the expressions themselves.
function adminSource() {
  return fs.readFileSync(path.join(projectRoot, "routes", "admin.js"), "utf8");
}
function serverSource() {
  return fs.readFileSync(path.join(projectRoot, "server-main.js"), "utf8");
}

describe("the security panel agrees with what the server actually does", function () {
  it("the server still opens TLS only with a certificate AND a key", function () {
    // The premise everything below rests on. If this changes, the panel's rule
    // has to change with it, and this test should be the thing that says so.
    assert.match(serverSource(), /if \(fs\.existsSync\(TLS_CERT\) && tlsKeyAvailable\(\)\)/,
      "server-main.js no longer gates TLS on cert AND key — re-derive the panel's rule");
  });

  it("resolves the sealed key from the configured key path, as the server does", function () {
    // server-main.js builds TLS_KEY_SEALED as TLS_KEY + ".sealed". Reading the
    // fixed default instead reports a running listener as disabled whenever
    // TLS_KEY points somewhere else — the same class of wrong as the row this
    // file exists to fix, pointed the other way.
    assert.match(serverSource(), /var TLS_KEY_SEALED = TLS_KEY \+ "\.sealed";/,
      "server-main.js derives the sealed path from TLS_KEY");
    assert.match(adminSource(), /nodeFs\.existsSync\(tlsKeyPath \+ "\.sealed"\)/,
      "and the panel must derive it the same way, not from the fixed constant");
  });

  it("reports the listener the server actually started, not a re-reading of files", function () {
    // The structural fix. Whether TLS is serving depends on the certificate,
    // the key, and the key loading under the configured sealed-key mode — every
    // re-derivation is a second implementation of that rule, and the panel's
    // copy had already drifted once. server-main records what happened; the
    // panel asks.
    var src = adminSource();
    assert.match(src, /var tlsReported = runtimeState\.get\("tlsEnabled"\);/,
      "the panel must read the recorded listener state");
    assert.match(src, /var hardReported = runtimeState\.get\("hardMtls"\);/,
      "and the recorded enforcement state");
    assert.match(src, /status: tlsServing \? "ok" : "warn"/,
      "the TLS row's status must come from that");
    assert.ok(!/status: tlsPlainExists \|\| tlsSealedExists \? "ok"/.test(src),
      "the key-only predicate must be gone");

    var srv = serverSource();
    assert.match(srv, /runtimeState\.set\(\{ tlsEnabled: true, hardMtls: hardMtls \}\)/,
      "the server must record the success case");
    assert.match(srv, /runtimeState\.set\(\{ tlsEnabled: false, hardMtls: false \}\)/,
      "and the no-certificate and failed-to-load cases");
  });

  it("treats an unrecorded state as unknown rather than as off", function () {
    // Reporting a protection as disabled because nothing told the panel is the
    // same defect inverted, so the fallback is the file check, not false.
    var src = adminSource();
    assert.match(src, /tlsReported === null \? \(tlsCertExists && tlsKeyExists\) : tlsReported/,
      "an unrecorded TLS state must fall back to inspection, not to false");
    assert.match(src, /hardReported === null/,
      "same for the enforcement state");
  });

  it("a key without a certificate is named as the reason, not reported as enabled", function () {
    var src = adminSource();
    assert.match(src, /key present, certificate missing/,
      "the half-configured case is the one an operator has to act on, so it must say so");
  });

  it("hard mTLS is only claimed when there is a TLS listener to enforce it", function () {
    // Recorded state first — the server knows whether it passed
    // rejectUnauthorized to a listener. The fallback still requires a listener,
    // because hard enforcement without one enforces nothing.
    var src = adminSource();
    assert.match(src, /\? \(enforceMtlsStrict === "true" && caExists && tlsServing\)\s*\n?\s*: hardReported;/,
      "the fallback must still require a listener, and the recorded value must win");
  });

  it("and when it is asked for but impossible, the guidance says why", function () {
    var src = adminSource();
    assert.match(src, /hard enforcement is a TLS-listener setting and this server is running without TLS/,
      "repeating 'set ENFORCE_MTLS_STRICT=true' to someone who already has is not guidance");
  });

  it("that guidance does not deny enforcement the app layer is still doing", function () {
    // The trap in fixing a row that overstated protection is understating it in
    // the next configuration along. With ENFORCE_MTLS=true the middleware does
    // require a client certificate, so telling the operator none is required
    // would be the same defect pointed the other way.
    var src = adminSource();
    assert.match(src, /mtlsSoftEnforced\s*\n?\s*\?\s*"ENFORCE_MTLS_STRICT=true is set, but hard enforcement/,
      "the no-TLS guidance must branch on whether soft enforcement is active");
    assert.match(src, /Client certificates are still required by the app-layer check/,
      "and must say so when it is");
  });
});
