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

// Drives the gate/allow/deny/refuse control-flow branches that the
// revocation-source test doesn't reach: no-opts construction, allow /
// deny list matching, custom audit-action + error-message, the
// connection-fallback + pre-populated-peerCert + getPeerCertificate-throws
// socket-read paths, an unfingerprintable cert, and the subject-null
// refusal/emit branches — all through the real b.middleware.requireMtls
// consumer path with a real CA-issued leaf DER.
async function testGateControlFlowBranches() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "mtls-cov-"));
  try {
    var ca = b.mtlsCa.create({ dataDir: dir, caKeySealedMode: "disabled" });
    await ca.initCA();
    var leaf = await ca.generateClientCert({ cn: "cov-peer" });
    var der = new nodeCrypto.X509Certificate(leaf.cert).raw;
    var fp = b.crypto.hashCertFingerprint(der);
    var peerSubj = { raw: der, subject: { CN: "cov-peer" } };
    var peerNoSubj = { raw: der };            // no subject → subject-null branches
    var otherFp = "AB:CD:EF:01:23:45";        // a well-formed but non-matching entry

    function drive(gate, req) {
      var res = _mockRes(); var nextCalled = false;
      gate(req, res, function () { nextCalled = true; });
      return { next: nextCalled, res: res };
    }

    // Construction with no opts at all (opts = opts || {}).
    var gateNoOpts = b.middleware.requireMtls();
    check("requireMtls() with no opts returns a middleware function", typeof gateNoOpts === "function");

    // denyList array is normalized + a matching fingerprint is refused.
    var denyDenied = null;
    var denyGate = b.middleware.requireMtls({
      audit: false, denyList: [fp.colon],
      onDeny: function (req, res, info) { denyDenied = info; },
    });
    var denyR = drive(denyGate, _mockReq({ authorized: true, peerCert: peerSubj }));
    check("denyList: a peer whose fingerprint is on the deny-list is refused",
          denyR.next === false && denyDenied && denyDenied.reason === "fingerprint-on-deny-list");
    check("denyList refusal carries the peer fingerprint + subject",
          denyDenied.fingerprint === fp.colon && denyDenied.subject === "cov-peer");

    // denyList present but NOT matching → the request proceeds (isCertRevoked false branch).
    var denyMissR = drive(b.middleware.requireMtls({ audit: false, denyList: [otherFp] }),
                          _mockReq({ authorized: true, peerCert: peerSubj }));
    check("denyList: a peer not on the deny-list proceeds", denyMissR.next === true);

    // allowList array normalized; a non-matching fingerprint is refused.
    var notAllowedDenied = null;
    var allowGate = b.middleware.requireMtls({
      audit: false, fingerprintAllowList: [otherFp],
      onDeny: function (req, res, info) { notAllowedDenied = info; },
    });
    var allowR = drive(allowGate, _mockReq({ authorized: true, peerCert: peerSubj }));
    check("allowList: a peer whose fingerprint is NOT on the allow-list is refused",
          allowR.next === false && notAllowedDenied && notAllowedDenied.reason === "fingerprint-not-allowed");

    // allowList match → admitted, and the parsed fingerprint is attached to req.
    var matchReq = _mockReq({ authorized: true, peerCert: peerSubj });
    var matchR = drive(b.middleware.requireMtls({ audit: false, fingerprintAllowList: [fp.colon] }), matchReq);
    check("allowList match admits and attaches req.peerFingerprint",
          matchR.next === true && matchReq.peerFingerprint && matchReq.peerFingerprint.colon === fp.colon);

    // onAuthenticated hook fires on success; peer has no subject (subject-null
    // emit branch); audit omitted → the audit-enabled _emit success path runs.
    var hookReq = _mockReq({ authorized: true, peerCert: peerNoSubj });
    var hookSeen = null;
    var hookR = drive(b.middleware.requireMtls({
      onAuthenticated: function (req, res, next) { hookSeen = req.peerFingerprint; next(); },
    }), hookReq);
    check("onAuthenticated hook fires on success and receives the attached fingerprint",
          hookR.next === true && hookSeen && hookSeen.colon === fp.colon);

    // Audit-enabled gate still refuses an unauthorized peer (the _emit denied branch).
    var auditRefuseR = drive(b.middleware.requireMtls({}), _mockReq({ authorized: false }));
    check("audit-enabled gate refuses an unauthorized peer 401",
          auditRefuseR.next === false && auditRefuseR.res._captured.status === 401);

    // Custom auditAction + errorMessage flow through construction + the refusal body.
    var customR = drive(b.middleware.requireMtls({
      audit: false, auditAction: "svc.mesh", errorMessage: "peer cert mandatory",
    }), _mockReq({ authorized: false }));
    check("custom errorMessage surfaces in the refusal body",
          JSON.parse(customR.res._captured.body).error === "peer cert mandatory");

    // Peer cert read from req.connection when req.socket is absent.
    var connReq = { url: "/", method: "GET", headers: {},
      connection: { authorized: true, getPeerCertificate: function () { return peerSubj; } } };
    check("peer cert read from req.connection when req.socket is absent",
          drive(b.middleware.requireMtls({ audit: false }), connReq).next === true);

    // Neither socket nor connection → sock null → refused.
    var noSockR = drive(b.middleware.requireMtls({ audit: false }), { url: "/", method: "GET", headers: {} });
    check("no socket and no connection is refused 401",
          noSockR.next === false && noSockR.res._captured.status === 401);

    // A pre-populated req.peerCert is used WITHOUT calling getPeerCertificate.
    var preReq = { url: "/", method: "GET", headers: {}, peerCert: peerSubj,
      socket: { authorized: true, getPeerCertificate: function () { throw new Error("must not be called"); } } };
    check("a pre-populated req.peerCert is used without calling getPeerCertificate",
          drive(b.middleware.requireMtls({ audit: false }), preReq).next === true);

    // getPeerCertificate throwing is caught → peerCert stays null → refused.
    var throwReq = { url: "/", method: "GET", headers: {},
      socket: { authorized: true, getPeerCertificate: function () { throw new Error("tls state gone"); } } };
    var throwR = drive(b.middleware.requireMtls({ audit: false }), throwReq);
    check("a getPeerCertificate that throws is caught and the request refused 401",
          throwR.next === false && throwR.res._captured.status === 401);

    // getPeerCertificate returning a falsy value → peerCert null → refused (the `|| null` arm).
    var nullCertReq = { url: "/", method: "GET", headers: {},
      socket: { authorized: true, getPeerCertificate: function () { return null; } } };
    var nullCertR = drive(b.middleware.requireMtls({ audit: false }), nullCertReq);
    check("a null getPeerCertificate result is refused 401",
          nullCertR.next === false && nullCertR.res._captured.status === 401);

    // Authorized peer with a cert object that has no raw DER → no-peer-cert.
    var emptyDenied = null;
    var emptyR = drive(b.middleware.requireMtls({
      audit: false, onDeny: function (req, res, info) { emptyDenied = info; },
    }), _mockReq({ authorized: true, peerCert: {} }));
    check("an authorized peer with no cert DER is refused (no-peer-cert)",
          emptyR.next === false && emptyDenied && emptyDenied.reason === "no-peer-cert");

    // A raw that cannot be fingerprinted (not a Buffer / PEM) → fingerprint-failed.
    var fpFailDenied = null;
    var fpFailR = drive(b.middleware.requireMtls({
      audit: false, onDeny: function (req, res, info) { fpFailDenied = info; },
    }), _mockReq({ authorized: true, peerCert: { raw: 12345 } }));
    check("a peer cert whose raw cannot be fingerprinted is refused (fingerprint-failed)",
          fpFailR.next === false && fpFailDenied && fpFailDenied.reason === "fingerprint-failed");

    // A revoked cert with NO subject → fingerprint-revoked with a null subject.
    var revNoSubjDenied = null;
    var revR = drive(b.middleware.requireMtls({
      audit: false, revocationSource: { isRevoked: function () { return true; } },
      onDeny: function (req, res, info) { revNoSubjDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerNoSubj }));
    check("a revoked cert with no subject is refused with a null subject in the refusal",
          revR.next === false && revNoSubjDenied && revNoSubjDenied.reason === "fingerprint-revoked" &&
          revNoSubjDenied.subject === null);

    // A revocationSource that throws a NON-Error value fails closed and stringifies it.
    var strThrowDenied = null;
    var strThrowR = drive(b.middleware.requireMtls({
      audit: false, revocationSource: { isRevoked: function () { var nonErr = "registry offline"; throw nonErr; } },
      onDeny: function (req, res, info) { strThrowDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerSubj }));
    check("a revocationSource that throws a non-Error value fails closed with a stringified diagnostic",
          strThrowR.next === false && strThrowDenied && strThrowDenied.reason === "revocation-check-failed" &&
          strThrowDenied.error === "registry offline");

    // A non-string / empty allow-or-deny entry is refused at construction.
    var badFpErr = null;
    try { b.middleware.requireMtls({ denyList: [""] }); } catch (e) { badFpErr = e; }
    check("an empty-string deny-list entry is refused at construction",
          badFpErr && badFpErr.code === "require-mtls/bad-fingerprint");
    var badAllowErr = null;
    try { b.middleware.requireMtls({ fingerprintAllowList: [123] }); } catch (e) { badAllowErr = e; }
    check("a non-string allow-list entry is refused at construction",
          badAllowErr && badAllowErr.code === "require-mtls/bad-fingerprint");

    // onAuthenticated throwing → refused with reason on-authenticated-threw.
    var hookThrewDenied = null;
    var hookThrewR = drive(b.middleware.requireMtls({
      audit: false, onAuthenticated: function () { throw new Error("downstream blew up"); },
      onDeny: function (req, res, info) { hookThrewDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerSubj }));
    check("an onAuthenticated hook that throws is caught and the request refused",
          hookThrewR.next === false && hookThrewDenied && hookThrewDenied.reason === "on-authenticated-threw");

    // A deny-list match on a peer with NO subject → refusal reports a null subject.
    var denyNoSubjDenied = null;
    var denyNoSubjR = drive(b.middleware.requireMtls({
      audit: false, denyList: [fp.colon],
      onDeny: function (req, res, info) { denyNoSubjDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerNoSubj }));
    check("a deny-listed peer with no subject is refused with a null subject",
          denyNoSubjR.next === false && denyNoSubjDenied &&
          denyNoSubjDenied.reason === "fingerprint-on-deny-list" && denyNoSubjDenied.subject === null);

    // A non-matching allow-list on a peer with NO subject → refusal reports a null subject.
    var allowNoSubjDenied = null;
    var allowNoSubjR = drive(b.middleware.requireMtls({
      audit: false, fingerprintAllowList: [otherFp],
      onDeny: function (req, res, info) { allowNoSubjDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerNoSubj }));
    check("a peer with no subject not on the allow-list is refused with a null subject",
          allowNoSubjR.next === false && allowNoSubjDenied &&
          allowNoSubjDenied.reason === "fingerprint-not-allowed" && allowNoSubjDenied.subject === null);

    // onAuthenticated throwing a NON-Error value → the diagnostic stringifies it.
    var hookStrDenied = null;
    var hookStrR = drive(b.middleware.requireMtls({
      audit: false, onAuthenticated: function () { var nonErr = "handler string failure"; throw nonErr; },
      onDeny: function (req, res, info) { hookStrDenied = info; },
    }), _mockReq({ authorized: true, peerCert: peerSubj }));
    check("an onAuthenticated hook that throws a non-Error value fails closed with a stringified diagnostic",
          hookStrR.next === false && hookStrDenied &&
          hookStrDenied.reason === "on-authenticated-threw" && hookStrDenied.error === "handler string failure");
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
  await testGateControlFlowBranches();

  console.log("OK — requireMtls tests — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}
