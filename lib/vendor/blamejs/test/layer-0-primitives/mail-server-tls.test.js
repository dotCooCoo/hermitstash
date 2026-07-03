// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

async function _mintTestCert() {
  // Use the framework's mtls engine to mint a self-signed cert. The
  // CA shape (caCertPem + caKeyPem) is itself a valid self-signed pair
  // that node:tls.createSecureContext accepts.
  var ca = await b.mtlsEngine.generateCa({ generation: 1 });
  return { certPem: ca.caCertPem, keyPem: ca.caKeyPem };
}

function _mkTmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-mail-tls-" + label + "-"));
}

function _writeFile(p, content) {
  fs.writeFileSync(p, content);
  return p;
}

async function run() {
  var modSurface = b.mail.server.tls;
  check("surface: context is fn",            typeof modSurface.context === "function");
  check("surface: MailServerTlsError class", typeof modSurface.MailServerTlsError === "function");
  check("surface: upgradeSocket is fn",       typeof modSurface.upgradeSocket === "function");
  check("surface: upgradeLineProtocol is fn", typeof modSurface.upgradeLineProtocol === "function");

  // ---- upgradeLineProtocol: config-time validation (§8 entry-point) ----
  var ulpBad = [];
  try { modSurface.upgradeLineProtocol(); }              catch (e) { ulpBad.push(e); }
  try { modSurface.upgradeLineProtocol({}); }            catch (e) { ulpBad.push(e); }
  try { modSurface.upgradeLineProtocol({ state: {} }); } catch (e) { ulpBad.push(e); }
  check("upgradeLineProtocol throws on missing opts",  ulpBad[0] && /opts required/.test(ulpBad[0].message));
  check("upgradeLineProtocol throws on missing state", ulpBad[1] && /state/.test(ulpBad[1].message));
  check("upgradeLineProtocol throws on missing drain", ulpBad[2] && /drain/.test(ulpBad[2].message));

  // ---- upgradeLineProtocol: the STARTTLS-injection drain runs BEFORE the
  // upgrade (CVE-2021-33515 / CVE-2021-38371). With a non-socket the inner
  // upgradeSocket throws, but the pre-handshake state MUST already be wiped.
  var injState = {
    lineBuffer:     Buffer.from("A001 LOGIN pipelined-pre-handshake\r\n"),
    pendingLiteral: { bytes: 42 },
    authPending:    "half-sasl-token",
    tls:            false,
  };
  var injThrew = null;
  try {
    modSurface.upgradeLineProtocol({
      state:         injState,
      socket:        {},               // not a net.Socket → inner upgradeSocket throws
      secureContext: {},
      idleTimeoutMs: 1000,
      clearFields:   ["pendingLiteral", "authPending"],
      drain:         function () {},
      onError:       function () {},
    });
  } catch (e) { injThrew = e; }
  check("upgradeLineProtocol rejects a non-socket (via upgradeSocket)",
    injThrew && /plainSocket/.test(injThrew.message));
  check("injection drain: lineBuffer emptied even when the upgrade fails",
    injState.lineBuffer.length === 0);
  check("injection drain: clearFields[0] (pendingLiteral) nulled", injState.pendingLiteral === null);
  check("injection drain: clearFields[1] (authPending) nulled",    injState.authPending === null);

  // ---- happy path: plain PEM files load + return a SecureContext ----
  var tmp1 = _mkTmpDir("happy");
  try {
    var pair = await _mintTestCert();
    var certFile = _writeFile(path.join(tmp1, "cert.pem"), pair.certPem);
    var keyFile  = _writeFile(path.join(tmp1, "key.pem"),  pair.keyPem);
    var tlsCtx = b.mail.server.tls.context({ certFile: certFile, keyFile: keyFile });
    check("context: returns a handle with secureContext getter",
          tlsCtx && typeof tlsCtx.secureContext === "object" &&
          tlsCtx.secureContext !== null);
    check("context: reload is fn",        typeof tlsCtx.reload === "function");
    check("context: onReload is fn",      typeof tlsCtx.onReload === "function");
    check("context: stop is fn",          typeof tlsCtx.stop === "function");
    tlsCtx.stop();
  } finally {
    fs.rmSync(tmp1, { recursive: true, force: true });
  }

  // ---- bad-input refusals ----
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label,
      threw && threw.code && threw.code.indexOf(codeMatch) !== -1);
  }
  expectThrow("refuses missing opts",
    function () { b.mail.server.tls.context(); },
    "mail-server-tls/bad-opts");
  expectThrow("refuses missing certFile",
    function () { b.mail.server.tls.context({ keyFile: "/x" }); },
    "mail-server-tls/bad-cert-file");
  expectThrow("refuses missing keyFile",
    function () { b.mail.server.tls.context({ certFile: "/x" }); },
    "mail-server-tls/bad-key-file");
  expectThrow("refuses non-vault-shaped vault",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", vault: {} }); },
    "mail-server-tls/bad-vault");
  expectThrow("refuses non-boolean watch",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", watch: "yes" }); },
    "mail-server-tls/bad-watch");
  expectThrow("refuses pollMs below 1000",
    function () { b.mail.server.tls.context({ certFile: "/x", keyFile: "/y", pollMs: 100 }); },
    "mail-server-tls/bad-poll-ms");

  // ---- file-not-found surfaces typed error ----
  expectThrow("refuses unreadable certFile",
    function () { b.mail.server.tls.context({
      certFile: "/this/path/does/not/exist.pem",
      keyFile:  "/this/path/also/does/not/exist.pem",
    }); },
    "mail-server-tls/cert-unreadable");

  // ---- reload() rebuilds the context + fires onReload listeners ----
  var tmp3 = _mkTmpDir("reload");
  try {
    var pair1 = await _mintTestCert();
    var certFile3 = _writeFile(path.join(tmp3, "cert.pem"), pair1.certPem);
    var keyFile3  = _writeFile(path.join(tmp3, "key.pem"),  pair1.keyPem);
    var tlsCtx3 = b.mail.server.tls.context({ certFile: certFile3, keyFile: keyFile3 });
    var firstCtx = tlsCtx3.secureContext;
    var listenerCalls = 0;
    var lastSeenCtx = null;
    tlsCtx3.onReload(function (newCtx) { listenerCalls += 1; lastSeenCtx = newCtx; });

    // Simulate cert rotation — overwrite both files with a fresh pair
    var pair2 = await _mintTestCert();
    fs.writeFileSync(certFile3, pair2.certPem);
    fs.writeFileSync(keyFile3,  pair2.keyPem);
    var reloadedCtx = tlsCtx3.reload();

    check("reload: returns a fresh SecureContext",
      reloadedCtx && reloadedCtx !== firstCtx);
    check("reload: secureContext getter now returns the fresh one",
      tlsCtx3.secureContext === reloadedCtx);
    check("reload: fires onReload listeners",
      listenerCalls === 1);
    check("reload: listener receives the fresh context",
      lastSeenCtx === reloadedCtx);
    tlsCtx3.stop();
  } finally {
    fs.rmSync(tmp3, { recursive: true, force: true });
  }

  // ---- onReload rejects non-function ----
  var tmp4 = _mkTmpDir("badlistener");
  try {
    var pair4 = await _mintTestCert();
    var certFile4 = _writeFile(path.join(tmp4, "cert.pem"), pair4.certPem);
    var keyFile4  = _writeFile(path.join(tmp4, "key.pem"),  pair4.keyPem);
    var tlsCtx4 = b.mail.server.tls.context({ certFile: certFile4, keyFile: keyFile4 });
    var threw = null;
    try { tlsCtx4.onReload("not a fn"); } catch (e) { threw = e; }
    check("onReload: refuses non-function",
      threw && threw.code === "mail-server-tls/bad-listener");
    tlsCtx4.stop();
  } finally {
    fs.rmSync(tmp4, { recursive: true, force: true });
  }

  // ---- MX listener's no-tls-context error message points at this primitive ----
  var threwNoTls = null;
  try { b.mail.server.mx.create({ }); } catch (e) { threwNoTls = e; }
  check("MX no-tls-context error: points at b.mail.server.tls.context",
    threwNoTls && /b\.mail\.server\.tls\.context/.test(threwNoTls.message));
  check("MX no-tls-context error: points at b.acme for provisioning",
    threwNoTls && /b\.acme/.test(threwNoTls.message));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-server-tls] OK"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
