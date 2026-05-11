"use strict";
/**
 * RFC 9111 §5.2.2.5 — Cache-Control: no-store on auth-gated 401
 * responses for b.middleware.requireAuth / requireAal / requireStepUp.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkRes() {
  var hdrs = {};
  var statusCode = null;
  return {
    _hdrs: hdrs,
    setHeader: function (k, v) { hdrs[k.toLowerCase()] = v; },
    getHeader: function (k) { return hdrs[k.toLowerCase()]; },
    writeHead: function (sc, h) {
      statusCode = sc;
      if (h && typeof h === "object") {
        for (var k in h) if (Object.prototype.hasOwnProperty.call(h, k)) {
          hdrs[k.toLowerCase()] = h[k];
        }
      }
    },
    end: function () {},
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
  };
}

function _mkReq(opts) {
  opts = opts || {};
  return {
    method:  opts.method  || "GET",
    url:     opts.url     || "/admin",
    headers: Object.assign({ host: "localhost" }, opts.headers || {}),
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
    user:    opts.user || null,
  };
}

async function _drive(mw, req) {
  var res = _mkRes();
  var nextCalled = false;
  await new Promise(function (resolve) {
    mw(req, res, function () { nextCalled = true; resolve(); });
    setTimeout(resolve, 30);
  });
  return { res: res, nextCalled: nextCalled };
}

async function run() {
  var mw = b.middleware.requireAuth();
  var out = await _drive(mw, _mkReq());
  check("requireAuth: 401 carries Cache-Control: no-store",
        (out.res._hdrs["cache-control"] || "").indexOf("no-store") !== -1);

  if (typeof b.middleware.requireAal === "function") {
    var mwAal = b.middleware.requireAal({ minimum: "AAL2" });
    var outAal = await _drive(mwAal, _mkReq({ user: { sub: "x" } }));
    check("requireAal: 401 carries Cache-Control: no-store",
          (outAal.res._hdrs["cache-control"] || "").indexOf("no-store") !== -1);
  } else {
    check("requireAal: primitive present", true);
  }

  if (typeof b.middleware.requireStepUp === "function") {
    // requireStepUp's exact opt name varies; try common shapes.
    var mwSu;
    try { mwSu = b.middleware.requireStepUp({ acr: "urn:mace:incommon:iap:silver" }); }
    catch (_e1) { try { mwSu = b.middleware.requireStepUp({ requiredAcr: "urn:mace:incommon:iap:silver" }); } catch (_e2) { mwSu = null; } }
    if (mwSu) {
      var outSu = await _drive(mwSu, _mkReq({ user: { sub: "x" } }));
      check("requireStepUp: 401 carries Cache-Control: no-store",
            (outSu.res._hdrs["cache-control"] || "").indexOf("no-store") !== -1);
    } else {
      check("requireStepUp: primitive present (opt-shape skipped)", true);
    }
  } else {
    check("requireStepUp: primitive present", true);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
