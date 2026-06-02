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
  var ended = false;
  var origEnd = res.end;
  res.end = function (b) { ended = true; return origEnd.call(res, b); };
  mw(req, res, function () { nextCalled = true; });
  await helpers.waitUntil(function () { return ended || nextCalled; }, {
    timeoutMs: 5000,
    label:     "scim-server: middleware resolves (response written or next() called)",
  });
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
  check("BulkRequest URN exported",       scimMod.SCIM_MESSAGE_BULK_REQUEST === "urn:ietf:params:scim:api:messages:2.0:BulkRequest");
  check("BulkResponse URN exported",      scimMod.SCIM_MESSAGE_BULK_RESPONSE === "urn:ietf:params:scim:api:messages:2.0:BulkResponse");

  await _runBulkTests();
}

// RFC 7644 §3.7 — /Bulk operations.
function _mkUsers() {
  return {
    _records: new Map(),
    _seq:     0,
    async create(rec) {
      var id = "u-" + (++this._seq);
      var out = Object.assign({ id: id, meta: { resourceType: "User" } }, rec);
      this._records.set(id, out);
      return out;
    },
    async read(id)        { return this._records.get(id) || null; },
    async update(id, rec) { var r = Object.assign({}, rec, { id: id }); this._records.set(id, r); return r; },
    async patch(id, ops)  { var r = this._records.get(id); ops.forEach(function (o) { if (o.op === "replace") r[o.path] = o.value; }); return r; },
    async remove(id)      { this._records.delete(id); },
    async list()          { return { totalResults: this._records.size, Resources: Array.from(this._records.values()) }; },
  };
}

function _mkGroups() {
  return {
    _records:   new Map(),
    _seq:       0,
    _lastCreate: null,
    async create(rec) {
      var id = "g-" + (++this._seq);
      var out = Object.assign({ id: id, meta: { resourceType: "Group" } }, rec);
      this._records.set(id, out);
      this._lastCreate = out;
      return out;
    },
    async read(id)        { return this._records.get(id) || null; },
    async update(id, rec) { var r = Object.assign({}, rec, { id: id }); this._records.set(id, r); return r; },
    async patch(id, ops)  { var r = this._records.get(id); return r; },
    async remove(id)      { this._records.delete(id); },
    async list()          { return { totalResults: this._records.size, Resources: Array.from(this._records.values()) }; },
  };
}

async function _bulkBody(mw, ops, extra) {
  var body = Object.assign({
    schemas:    ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    Operations: ops,
  }, extra || {});
  return _drive(mw, { method: "POST", url: "/scim/v2/Bulk", headers: {}, body: body });
}

async function _runBulkTests() {
  // Bulk disabled by default — SPC stays unsupported, /Bulk returns 501.
  var off = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers() });
  var offSpc = await _drive(off, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} });
  check("bulk default: SPC supported=false", JSON.parse(offSpc.res._body()).bulk.supported === false);
  var offBulk = await _bulkBody(off, []);
  check("bulk default: /Bulk → 501",         offBulk.res._sc() === 501);

  // Enabled — SPC advertises supported=true + configured maxOperations.
  var users  = _mkUsers();
  var groups = _mkGroups();
  var mw = b.middleware.scimServer({
    basePath: "/scim/v2",
    users:    users,
    groups:   groups,
    bulk:     { maxOperations: 3 },
  });
  var onSpc = JSON.parse((await _drive(mw, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} })).res._body());
  check("bulk enabled: SPC supported=true",  onSpc.bulk.supported === true);
  check("bulk enabled: SPC maxOperations",   onSpc.bulk.maxOperations === 3);

  // create + update + delete in one request → per-op statuses.
  var seedUser = await users.create({ userName: "seed" });   // u-1
  var batch = await _bulkBody(mw, [
    { method: "POST",   path: "/Users", bulkId: "newuser",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "alice" } },
    { method: "PUT",    path: "/Users/" + seedUser.id,
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "seed-renamed" } },
    { method: "DELETE", path: "/Users/" + seedUser.id },
  ]);
  var resp = JSON.parse(batch.res._body());
  check("bulk: 200 envelope",                batch.res._sc() === 200);
  check("bulk: BulkResponse schema",         resp.schemas.indexOf("urn:ietf:params:scim:api:messages:2.0:BulkResponse") !== -1);
  check("bulk: 3 op results",                resp.Operations.length === 3);
  check("bulk: POST → 201",                  resp.Operations[0].status === "201");
  check("bulk: POST echoes bulkId",          resp.Operations[0].bulkId === "newuser");
  check("bulk: POST location present",       typeof resp.Operations[0].location === "string");
  check("bulk: PUT → 200",                   resp.Operations[1].status === "200");
  check("bulk: DELETE → 204",                resp.Operations[2].status === "204");
  check("bulk: DELETE has no response body", resp.Operations[2].response === undefined);

  // A bulk POST whose resource body is missing its SCIM schema is rejected
  // per-op (the same gate the singleton POST/PUT routes apply), not
  // persisted through the adapter.
  var badSchema = await _bulkBody(mw, [
    { method: "POST", path: "/Users", data: { userName: "noschema" } },
  ]);
  var badSchemaResp = JSON.parse(badSchema.res._body());
  check("bulk: POST with missing schema → per-op 400",
        badSchemaResp.Operations.length === 1 && badSchemaResp.Operations[0].status === "400");

  // bulkId cross-reference: create a user, then a group whose member
  // references the just-created user by "bulkId:<id>" (RFC 7644 §3.7.2).
  var users2  = _mkUsers();
  var groups2 = _mkGroups();
  var mw2 = b.middleware.scimServer({ basePath: "/scim/v2", users: users2, groups: groups2, bulk: { maxOperations: 10 } });
  var ref = await _bulkBody(mw2, [
    { method: "POST", path: "/Users", bulkId: "bob",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "bob" } },
    { method: "POST", path: "/Groups", bulkId: "admins",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Admins",
              members: [{ value: "bulkId:bob" }] } },
  ]);
  var refResp = JSON.parse(ref.res._body());
  check("bulk ref: both succeed",            refResp.Operations[0].status === "201" && refResp.Operations[1].status === "201");
  var createdUserId = users2._records.size === 1 ? Array.from(users2._records.keys())[0] : null;
  var groupMembers  = groups2._lastCreate && groups2._lastCreate.members;
  check("bulk ref: bulkId resolved to id",   Array.isArray(groupMembers) && groupMembers[0].value === createdUserId);
  check("bulk ref: ref not left as token",   groupMembers[0].value.indexOf("bulkId:") === -1);

  // over-maxOperations → 413, no operation dispatched.
  var users3 = _mkUsers();
  var mw3 = b.middleware.scimServer({ basePath: "/scim/v2", users: users3, bulk: { maxOperations: 1 } });
  var tooMany = await _bulkBody(mw3, [
    { method: "POST", path: "/Users", bulkId: "a", data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "a" } },
    { method: "POST", path: "/Users", bulkId: "b", data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "b" } },
  ]);
  check("bulk: over-maxOperations → 413",    tooMany.res._sc() === 413);
  check("bulk: over-max scimType=tooMany",   JSON.parse(tooMany.res._body()).scimType === "tooMany");
  check("bulk: over-max dispatched nothing",  users3._records.size === 0);

  // failOnErrors short-circuits at the first error.
  var users4 = _mkUsers();
  var failing = {
    create: async function () { var e = new Error("upstream conflict"); e.statusCode = 409; e.scimType = "uniqueness"; throw e; },
    read: users4.read.bind(users4), update: users4.update.bind(users4),
    patch: users4.patch.bind(users4), remove: users4.remove.bind(users4), list: users4.list.bind(users4),
  };
  var mw4 = b.middleware.scimServer({ basePath: "/scim/v2", users: failing, bulk: { maxOperations: 10 } });
  var short = await _bulkBody(mw4, [
    { method: "POST", path: "/Users", bulkId: "x", data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "x" } },
    { method: "POST", path: "/Users", bulkId: "y", data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "y" } },
    { method: "POST", path: "/Users", bulkId: "z", data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "z" } },
  ], { failOnErrors: 1 });
  var shortResp = JSON.parse(short.res._body());
  check("bulk failOnErrors: stops after 1",  shortResp.Operations.length === 1);
  check("bulk failOnErrors: error carries status", shortResp.Operations[0].status === "409");
  check("bulk failOnErrors: error has body", shortResp.Operations[0].response.schemas.indexOf("urn:ietf:params:scim:api:messages:2.0:Error") !== -1);

  // config-time refusal: non-integer cap throws at create time.
  var threwCap = false;
  try { b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: -5 } }); }
  catch (e) { threwCap = /bad-bulk-max-operations/.test(e.code || ""); }
  check("bulk: bad maxOperations refused",   threwCap);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
             function (e) { process.exitCode = 1; throw e; });
}
