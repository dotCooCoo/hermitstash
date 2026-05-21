"use strict";
// b.middleware.scimServer — SCIM 2.0 server middleware.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkRes() {
  var hdrs = {};
  var sc = null;
  var body = "";
  return {
    setHeader: function (k, v) { hdrs[k.toLowerCase()] = v; },
    writeHead: function (s, h) { sc = s; if (h) Object.keys(h).forEach(function (k) { hdrs[k.toLowerCase()] = h[k]; }); },
    end:       function (b) { if (b) body = b; },
    _hdrs:     hdrs,
    _sc:       function () { return sc; },
    _body:     function () { return body; },
  };
}

async function _drive(mw, req) {
  var res = _mkRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  await helpers.passiveObserve(50, "scim-server: middleware short-circuit window");
  return { res: res, nextCalled: nextCalled };
}

async function run() {
  var users = {
    _records: new Map(),
    async create(rec) {
      var id = "u-" + (this._records.size + 1);
      var out = Object.assign({ id: id, meta: { resourceType: "User" } }, rec);
      this._records.set(id, out);
      return out;
    },
    async read(id)             { return this._records.get(id) || null; },
    async update(id, rec)      { var r = Object.assign({}, rec, { id: id }); this._records.set(id, r); return r; },
    async patch(id, ops)       { var r = this._records.get(id); ops.forEach(function (o) { if (o.op === "replace") r[o.path] = o.value; }); return r; },
    async remove(id)           { this._records.delete(id); },
    async list()               { return { totalResults: this._records.size, Resources: Array.from(this._records.values()) }; },
  };

  var mw = b.middleware.scimServer({ basePath: "/scim/v2", users: users });
  check("returns middleware function",   typeof mw === "function");
  check("basePath default override",     mw.basePath === "/scim/v2");

  // ServiceProviderConfig — public
  var spc = await _drive(mw, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} });
  check("SPC: 200",                       spc.res._sc() === 200);
  check("SPC: bulk disabled",             JSON.parse(spc.res._body()).bulk.supported === false);

  // ResourceTypes
  var rt = await _drive(mw, { method: "GET", url: "/scim/v2/ResourceTypes", headers: {} });
  check("ResourceTypes: 200",             rt.res._sc() === 200);

  // Schemas
  var sc = await _drive(mw, { method: "GET", url: "/scim/v2/Schemas", headers: {} });
  check("Schemas: 200",                   sc.res._sc() === 200);

  // Unknown path — next() called
  var other = await _drive(mw, { method: "GET", url: "/api/users", headers: {} });
  check("non-SCIM path: next() called",   other.nextCalled);

  // Unknown SCIM resource — 404
  var unknown = await _drive(mw, { method: "GET", url: "/scim/v2/Widgets", headers: {} });
  check("unknown resource: 404",          unknown.res._sc() === 404);

  // Validation errors
  var threw = false;
  try { b.middleware.scimServer({ basePath: "/x" }); }
  catch (e) { threw = /no-users/.test(e.code || ""); }
  check("missing users impl refused",     threw);

  threw = false;
  try { b.middleware.scimServer({ users: { create: 1 } }); }
  catch (e) { threw = /bad-users-impl/.test(e.code || ""); }
  check("bad users impl refused",         threw);

  var scimMod = require("../../lib/middleware/scim-server");
  check("ALLOWED_FILTER_OPS exported",    Array.isArray(scimMod.ALLOWED_FILTER_OPS));
  check("SCIM_CORE_SCHEMA_USER exported", scimMod.SCIM_CORE_SCHEMA_USER === "urn:ietf:params:scim:schemas:core:2.0:User");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
             function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
