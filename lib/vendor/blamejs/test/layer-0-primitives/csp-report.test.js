"use strict";
/**
 * b.middleware.cspReport — Reporting-API endpoint for CSP / COEP /
 * COOP / Permissions-Policy violations.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var middleware = b.middleware.cspReport({});
  check("middleware.cspReport returns a function", typeof middleware === "function");

  var sent = {};
  var req = { method: "GET", headers: {} };
  var res = {
    headersSent: false,
    writeHead: function (s, h) { sent.status = s; sent.headers = h; },
    end:       function () { sent.ended = true; },
  };
  await middleware(req, res, function () {});
  check("middleware.cspReport: GET returns 405",
    sent.status === 405 && sent.ended === true);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[csp-report] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
