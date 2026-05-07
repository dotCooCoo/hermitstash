"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

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

(function run() {
  var requireMtls = b.middleware.requireMtls({ audit: false });
  var noPeerRes = _mockRes();
  requireMtls(_mockReq({ authorized: false }), noPeerRes, function () {});
  check("requireMtls refuses unauthorized peer 401", noPeerRes._captured.status === 401);

  console.log("OK — requireMtls tests");
})();
