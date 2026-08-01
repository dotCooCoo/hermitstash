// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var fs = require("fs");
var os = require("os");
var path = require("path");
var nodeCrypto = require("crypto");

function _mockReq(opts) {
  opts = opts || {};
  return {
    url: opts.url || "/",
    method: opts.method || "GET",
    headers: opts.headers || {},
    socket: opts.socket || { authorized: !!opts.authorized,
      authorizationError: opts.authorizationError || null,
      getPeerCertificate: function () { return opts.peerCert || {}; } },
  };
}
function _mockRes() {
  var captured = { status: 0, body: null, headers: {} };
  return {
    writableEnded: false,
    writeHead: function (s, h) { captured.status = s; if (h) Object.assign(captured.headers, h); },
    end: function (b) { captured.body = b; this.writableEnded = true; },
    _captured: captured,
  };
}

// A revocationSource (a b.mtlsCa handle) makes the CA's revocation registry —
// including revokeGeneration(), whose superseded-CA CRL a peer cannot verify —
// enforced at the gate by fingerprint, and it fails closed.
async function testRevocationSourceEnforcement() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "mtls-revsrc-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
    await ca.initCA();
    var leaf = await ca.generateClientCert({ cn: "peer-1" });
    var der = new nodeCrypto.X509Certificate(leaf.cert).raw;
    var peer = { raw: der, subject: { CN: "peer-1" } };

    var denied = null;
    var gate = b.middleware.requireMtls({
      audit: false, revocationSource: ca,
      onDeny: function (req, res, info) { denied = info; },
    });
    function _drive() {
      denied = null; var nextCalled = false;
      gate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { nextCalled = true; });
      return nextCalled;
    }

    check("revocationSource: an unrevoked peer cert is admitted", _drive() === true && denied === null);

    // Rotate, then revoke the whole gen-1 cohort — the fingerprint path the CRL can't cover.
    await ca.rotate({ generation: 2 });
    check("revokeGeneration revoked the gen-1 leaf", (await ca.revokeGeneration(2)).revoked === 1);

    var admittedAfter = _drive();
    check("revocationSource: the revoked cert is denied at the gate", admittedAfter === false);
    check("revocationSource: refusal reason is fingerprint-revoked",
          denied && denied.reason === "fingerprint-revoked");

    // A SERIAL-ONLY revocation (revoke(serial), fingerprint:null) must also be
    // enforced — via the peer certificate's serial number, not just fingerprint.
    var leaf2 = await ca.generateClientCert({ cn: "peer-2" });
    var peer2 = { raw: new nodeCrypto.X509Certificate(leaf2.cert).raw, subject: { CN: "peer-2" } };
    function _drive2() {
      denied = null; var n = false;
      gate(_mockReq({ authorized: true, peerCert: peer2 }), _mockRes(), function () { n = true; });
      return n;
    }
    check("revocationSource: an unrevoked peer-2 is admitted", _drive2() === true);
    await ca.revoke(leaf2.serialNumber);   // serial-only revocation (no fingerprint)
    check("revocationSource: a serial-only revocation is enforced at the gate", _drive2() === false);

    // A documented fingerprint-only source (strict 128-hex isRevoked, NO
    // isSerialRevoked) must NOT be called with a serial — that would throw and
    // fail-close every request. It should admit an unrevoked cert.
    var strictFpSource = {
      isRevoked: function (v) {
        if (typeof v !== "string" || v.length !== 128) throw new Error("expects a 128-hex SHA3-512 fingerprint");
        return false;
      },
    };
    var fpGate = b.middleware.requireMtls({ audit: false, revocationSource: strictFpSource });
    var fpNext = false;
    fpGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { fpNext = true; });
    check("a fingerprint-only revocationSource is not called with a serial (admits unrevoked)", fpNext === true);

    // Fail-closed: a source that throws refuses rather than admitting.
    var fcDenied = null;
    var fcGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { throw new Error("store down"); } },
      onDeny: function (req, res, info) { fcDenied = info; },
    });
    var fcNext = false;
    fcGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { fcNext = true; });
    check("revocationSource: a throwing source fails closed (denied, next not called)",
          fcNext === false && fcDenied && fcDenied.reason === "revocation-check-failed");

    // Fail-closed on a NON-BOOLEAN result: the contract is a SYNCHRONOUS boolean. An async source
    // (isRevoked returns a Promise) or one returning undefined/garbage must REFUSE — a Promise is
    // never === true, so silently treating it as not-revoked would ADMIT a possibly-revoked peer.
    var asyncDenied = null;
    var asyncGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return Promise.resolve(true); } },   // async, "revoked"
      onDeny: function (req, res, info) { asyncDenied = info; },
    });
    var asyncNext = false;
    asyncGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { asyncNext = true; });
    check("revocationSource: an async (Promise-returning) isRevoked fails closed",
          asyncNext === false && asyncDenied && asyncDenied.reason === "revocation-source-invalid");

    var undefDenied = null;
    var undefGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return undefined; } },
      onDeny: function (req, res, info) { undefDenied = info; },
    });
    var undefNext = false;
    undefGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { undefNext = true; });
    check("revocationSource: an undefined isRevoked result fails closed",
          undefNext === false && undefDenied && undefDenied.reason === "revocation-source-invalid");

    // A non-boolean isSerialRevoked result (with a proper boolean isRevoked) also refuses.
    var serDenied = null;
    var serGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return false; }, isSerialRevoked: function () { return Promise.resolve(true); } },
      onDeny: function (req, res, info) { serDenied = info; },
    });
    var serNext = false;
    serGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { serNext = true; });
    check("revocationSource: a non-boolean isSerialRevoked result fails closed",
          serNext === false && serDenied && serDenied.reason === "revocation-source-invalid");

    // A cert whose serial cannot be extracted (unparseable raw — e.g. a TLS-terminating proxy
    // prevalidated it, or an algorithm the local X.509 parser rejects) must be REFUSED when serial
    // enforcement is enabled (isSerialRevoked present) — never admitted after a skipped serial lookup,
    // which would let a serial-only revoke(serial) be bypassed.
    var serUnresDenied = null;
    var serUnresGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return false; }, isSerialRevoked: function () { return false; } },
      onDeny: function (req, res, info) { serUnresDenied = info; },
    });
    var serUnresNext = false;
    serUnresGate(_mockReq({ authorized: true, peerCert: { raw: Buffer.from("not-a-valid-der-cert"), subject: { CN: "unparseable" } } }),
                 _mockRes(), function () { serUnresNext = true; });
    check("a cert whose serial cannot be extracted is refused when serial enforcement is enabled",
          serUnresNext === false && serUnresDenied && serUnresDenied.reason === "serial-unresolved");

    // A null isRevoked result also refuses (typeof null is "object", so the diagnostic reports "null").
    var nullDenied = null;
    var nullGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return null; } },
      onDeny: function (req, res, info) { nullDenied = info; },
    });
    var nullNext = false;
    nullGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { nullNext = true; });
    check("revocationSource: a null isRevoked result fails closed with a null-typed diagnostic",
          nullNext === false && nullDenied && nullDenied.reason === "revocation-source-invalid" &&
          nullDenied.type === "null");

    // A null isSerialRevoked result likewise refuses (null-typed diagnostic).
    var nullSerDenied = null;
    var nullSerGate = b.middleware.requireMtls({
      audit: false,
      revocationSource: { isRevoked: function () { return false; }, isSerialRevoked: function () { return null; } },
      onDeny: function (req, res, info) { nullSerDenied = info; },
    });
    var nullSerNext = false;
    nullSerGate(_mockReq({ authorized: true, peerCert: peer }), _mockRes(), function () { nullSerNext = true; });
    check("revocationSource: a null isSerialRevoked result fails closed with a null-typed diagnostic",
          nullSerNext === false && nullSerDenied && nullSerDenied.reason === "revocation-source-invalid" &&
          nullSerDenied.type === "null");

    // A non-conforming revocationSource is rejected at construction.
    var ctorErr = null;
    try { b.middleware.requireMtls({ revocationSource: {} }); } catch (e) { ctorErr = e; }
    check("revocationSource without isRevoked() refused at construction",
          ctorErr && ctorErr.code === "require-mtls/bad-revocation-source");

    // A falsy non-object (false / 0 / "") must NOT be silently coerced to "no
    // source" — invalid security config fails at construction instead.
    var falsyErr = null;
    try { b.middleware.requireMtls({ revocationSource: false }); } catch (e) { falsyErr = e; }
    check("a falsy non-object revocationSource (false) is refused at construction",
          falsyErr && falsyErr.code === "require-mtls/bad-revocation-source");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function run() {
  var requireMtls = b.middleware.requireMtls({ audit: false });
  var noPeerRes = _mockRes();
  requireMtls(_mockReq({ authorized: false }), noPeerRes, function () {});
  check("requireMtls refuses unauthorized peer 401", noPeerRes._captured.status === 401);

  await testRevocationSourceEnforcement();

  console.log("OK — requireMtls tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
