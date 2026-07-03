// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.middleware.protectedResourceMetadata — draft-ietf-oauth-resource-metadata server.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkRes() {
  var hdrs = {};
  var sc = null;
  var body = "";
  return {
    _hdrs: hdrs, _sc: function () { return sc; }, _body: function () { return body; },
    setHeader: function (k, v) { hdrs[k.toLowerCase()] = v; },
    writeHead: function (s, h) { sc = s; if (h) Object.keys(h).forEach(function (k) { hdrs[k.toLowerCase()] = h[k]; }); },
    end:       function (b) { if (b) body = b; },
  };
}

function _drive(mw, req) {
  var res = _mkRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  return { res: res, nextCalled: nextCalled };
}

function run() {
  var mw = b.middleware.protectedResourceMetadata({
    resource: "https://api.example.com",
    authorizationServers: ["https://idp.example.com"],
    scopesSupported: ["read", "write"],
    dpopBoundAccessTokensRequired: true,
  });
  check("returns middleware function",  typeof mw === "function");
  check("exposes document",             mw.document.resource === "https://api.example.com");
  check("default path",                 mw.path === "/.well-known/oauth-protected-resource");

  var out = _drive(mw, { method: "GET", url: "/.well-known/oauth-protected-resource", headers: {} });
  check("GET: 200 status",              out.res._sc() === 200);
  check("GET: application/json type",   out.res._hdrs["content-type"] === "application/json");
  var doc = JSON.parse(out.res._body());
  check("GET: resource field",          doc.resource === "https://api.example.com");
  check("GET: AS list",                 doc.authorization_servers[0] === "https://idp.example.com");
  check("GET: dpop required",           doc.dpop_bound_access_tokens_required === true);

  var put = _drive(mw, { method: "PUT", url: "/.well-known/oauth-protected-resource", headers: {} });
  check("PUT: 405 method-not-allowed",  put.res._sc() === 405);

  var other = _drive(mw, { method: "GET", url: "/api/users", headers: {} });
  check("other path: next() called",    other.nextCalled);

  var threw = false;
  try { b.middleware.protectedResourceMetadata({ resource: "https://x", authorizationServers: [] }); }
  catch (e) { threw = /no-as/.test(e.code || ""); }
  check("empty AS list refused",        threw);

  threw = false;
  try { b.middleware.protectedResourceMetadata({ resource: "https://x", authorizationServers: ["https://y"], dpopSigningAlgValuesSupported: ["BOGUS"] }); }
  catch (e) { threw = /bad-dpop-alg/.test(e.code || ""); }
  check("unknown DPoP alg refused",     threw);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
