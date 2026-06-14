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
  await _runBulkRefOrderingTests();
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

// Deep-walk a value asserting no string carries an unresolved
// "bulkId:<id>" cross-reference token (RFC 7644 §3.7.2 — a literal token
// must never reach the adapter as if it were a real resource id).
function _containsBulkIdToken(value) {
  if (typeof value === "string") return /^bulkId:/.test(value);
  if (Array.isArray(value)) return value.some(_containsBulkIdToken);
  if (value && typeof value === "object") {
    return Object.keys(value).some(function (k) { return _containsBulkIdToken(value[k]); });
  }
  return false;
}

// A user adapter that records every data object it is handed so a test
// can assert the adapter NEVER received a literal "bulkId:<id>" token.
function _mkRecordingUsers() {
  return {
    _records:  new Map(),
    _seq:      0,
    _received: [],
    async create(rec) {
      this._received.push(rec);
      var id = "u-" + (++this._seq);
      var out = Object.assign({ id: id, meta: { resourceType: "User" } }, rec);
      this._records.set(id, out);
      return out;
    },
    async read(id)        { return this._records.get(id) || null; },
    async update(id, rec) { this._received.push(rec); var r = Object.assign({}, rec, { id: id }); this._records.set(id, r); return r; },
    async patch(id, ops)  { this._received.push(ops); var r = this._records.get(id); return r; },
    async remove(id)      { this._records.delete(id); },
    async list()          { return { totalResults: this._records.size, Resources: Array.from(this._records.values()) }; },
  };
}

function _mkRecordingGroups() {
  return {
    _records:    new Map(),
    _seq:        0,
    _received:   [],
    _lastCreate: null,
    async create(rec) {
      this._received.push(rec);
      var id = "g-" + (++this._seq);
      var out = Object.assign({ id: id, meta: { resourceType: "Group" } }, rec);
      this._records.set(id, out);
      this._lastCreate = out;
      return out;
    },
    async read(id)        { return this._records.get(id) || null; },
    async update(id, rec) { this._received.push(rec); var r = Object.assign({}, rec, { id: id }); this._records.set(id, r); return r; },
    async patch(id, ops)  { this._received.push(ops); var r = this._records.get(id); return r; },
    async remove(id)      { this._records.delete(id); },
    async list()          { return { totalResults: this._records.size, Resources: Array.from(this._records.values()) }; },
  };
}

// RFC 7644 §3.7.2 — forward references, circular references, undeclared
// references, and failed-dependency references.
async function _runBulkRefOrderingTests() {
  // --- Forward reference: the GROUP op references the USER op that comes
  // AFTER it in request order. Both must succeed and the token must be
  // substituted with the real id (success path, end-to-end).
  var fwdUsers  = _mkRecordingUsers();
  var fwdGroups = _mkRecordingGroups();
  var fwdMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: fwdUsers, groups: fwdGroups, bulk: { maxOperations: 10 },
  });
  var fwd = await _bulkBody(fwdMw, [
    { method: "POST", path: "/Groups", bulkId: "admins",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Admins",
              members: [{ value: "bulkId:carol" }] } },
    { method: "POST", path: "/Users", bulkId: "carol",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "carol" } },
  ]);
  var fwdResp = JSON.parse(fwd.res._body());
  check("bulk fwd-ref: 200 envelope",        fwd.res._sc() === 200);
  check("bulk fwd-ref: both succeed",        fwdResp.Operations[0].status === "201" && fwdResp.Operations[1].status === "201");
  // Response array stays in ORIGINAL request order (group first, user second).
  check("bulk fwd-ref: response in request order",
        fwdResp.Operations[0].bulkId === "admins" && fwdResp.Operations[1].bulkId === "carol");
  var fwdUserId  = Array.from(fwdUsers._records.keys())[0];
  var fwdMembers = fwdGroups._lastCreate && fwdGroups._lastCreate.members;
  check("bulk fwd-ref: token resolved to real id",
        Array.isArray(fwdMembers) && fwdMembers[0].value === fwdUserId);
  check("bulk fwd-ref: adapter never saw a literal token",
        !fwdGroups._received.some(_containsBulkIdToken) && !fwdUsers._received.some(_containsBulkIdToken));

  // --- Circular reference: two POSTs each reference the other's bulkId.
  // Both fail with HTTP 409 (RFC 7644 §3.7.1) and the adapter is NEVER
  // called with a literal token (in fact never called at all here).
  var cycUsers  = _mkRecordingUsers();
  var cycGroups = _mkRecordingGroups();
  var cycMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: cycUsers, groups: cycGroups, bulk: { maxOperations: 10 },
  });
  var cyc = await _bulkBody(cycMw, [
    { method: "POST", path: "/Users", bulkId: "ua",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "ua",
              manager: { value: "bulkId:ub" } } },
    { method: "POST", path: "/Users", bulkId: "ub",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "ub",
              manager: { value: "bulkId:ua" } } },
  ]);
  var cycResp = JSON.parse(cyc.res._body());
  check("bulk circular: 200 envelope",       cyc.res._sc() === 200);
  check("bulk circular: 2 results in order", cycResp.Operations.length === 2 &&
        cycResp.Operations[0].bulkId === "ua" && cycResp.Operations[1].bulkId === "ub");
  check("bulk circular: both fail 409",      cycResp.Operations[0].status === "409" && cycResp.Operations[1].status === "409");
  check("bulk circular: adapter never called with token",
        !cycUsers._received.some(_containsBulkIdToken));
  check("bulk circular: nothing persisted",  cycUsers._records.size === 0);

  // --- Undeclared reference: a member points at a bulkId no operation
  // declares — that op fails invalidValue; the well-formed op succeeds.
  var undUsers  = _mkRecordingUsers();
  var undGroups = _mkRecordingGroups();
  var undMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: undUsers, groups: undGroups, bulk: { maxOperations: 10 },
  });
  var und = await _bulkBody(undMw, [
    { method: "POST", path: "/Users", bulkId: "real",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "real" } },
    { method: "POST", path: "/Groups", bulkId: "grp",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "G",
              members: [{ value: "bulkId:ghost" }] } },
  ]);
  var undResp = JSON.parse(und.res._body());
  check("bulk undeclared: real op succeeds", undResp.Operations[0].status === "201");
  check("bulk undeclared: ref op fails 400", undResp.Operations[1].status === "400" &&
        undResp.Operations[1].response.scimType === "invalidValue");
  check("bulk undeclared: group adapter never saw token",
        !undGroups._received.some(_containsBulkIdToken));
  check("bulk undeclared: no group persisted", undGroups._records.size === 0);

  // --- Failed dependency: the creating op fails, so the op that
  // references it must fail invalidValue rather than receive the token.
  var depUsersBase = _mkRecordingUsers();
  var depUsers = {
    _records: depUsersBase._records,
    _received: depUsersBase._received,
    create: async function (rec) {
      depUsersBase._received.push(rec);
      var e = new Error("user create rejected"); e.statusCode = 409; e.scimType = "uniqueness"; throw e;
    },
    read: depUsersBase.read.bind(depUsersBase), update: depUsersBase.update.bind(depUsersBase),
    patch: depUsersBase.patch.bind(depUsersBase), remove: depUsersBase.remove.bind(depUsersBase),
    list: depUsersBase.list.bind(depUsersBase),
  };
  var depGroups = _mkRecordingGroups();
  var depMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: depUsers, groups: depGroups, bulk: { maxOperations: 10 },
  });
  var dep = await _bulkBody(depMw, [
    { method: "POST", path: "/Users", bulkId: "willfail",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "willfail" } },
    { method: "POST", path: "/Groups", bulkId: "grp",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "G",
              members: [{ value: "bulkId:willfail" }] } },
  ]);
  var depResp = JSON.parse(dep.res._body());
  check("bulk failed-dep: creator fails 409", depResp.Operations[0].status === "409");
  check("bulk failed-dep: dependent fails 400 invalidValue",
        depResp.Operations[1].status === "400" && depResp.Operations[1].response.scimType === "invalidValue");
  check("bulk failed-dep: group adapter never saw token",
        !depGroups._received.some(_containsBulkIdToken));
  check("bulk failed-dep: no group persisted", depGroups._records.size === 0);

  // --- Backward reference unchanged: a member references an EARLIER POST.
  var bwUsers  = _mkRecordingUsers();
  var bwGroups = _mkRecordingGroups();
  var bwMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: bwUsers, groups: bwGroups, bulk: { maxOperations: 10 },
  });
  var bw = await _bulkBody(bwMw, [
    { method: "POST", path: "/Users", bulkId: "dave",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "dave" } },
    { method: "POST", path: "/Groups", bulkId: "team",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "Team",
              members: [{ value: "bulkId:dave" }] } },
  ]);
  var bwResp = JSON.parse(bw.res._body());
  check("bulk back-ref: both succeed",       bwResp.Operations[0].status === "201" && bwResp.Operations[1].status === "201");
  var bwUserId  = Array.from(bwUsers._records.keys())[0];
  var bwMembers = bwGroups._lastCreate && bwGroups._lastCreate.members;
  check("bulk back-ref: token resolved",     Array.isArray(bwMembers) && bwMembers[0].value === bwUserId);
  check("bulk back-ref: adapter never saw token",
        !bwGroups._received.some(_containsBulkIdToken));

  // --- PATH references (RFC 7644 §3.7.2) — a bulkId can appear as the
  // resource id in an operation's path ("PATCH /Users/bulkId:u1"), not
  // just in operation data. Forward path refs order like data refs and
  // the path token is substituted with the real id before dispatch.
  var pthUsers = _mkRecordingUsers();
  var pthPatchedIds = [];
  var pthPatchInner = pthUsers.patch.bind(pthUsers);
  pthUsers.patch = async function (id, ops) { pthPatchedIds.push(id); return pthPatchInner(id, ops); };
  var pthMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: pthUsers, bulk: { maxOperations: 10 },
  });
  var pth = await _bulkBody(pthMw, [
    { method: "PATCH", path: "/Users/bulkId:newbie",
      data: { Operations: [{ op: "replace", path: "active", value: true }] } },
    { method: "POST", path: "/Users", bulkId: "newbie",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "newbie" } },
  ]);
  var pthResp = JSON.parse(pth.res._body());
  check("bulk path-ref: 200 envelope",      pth.res._sc() === 200);
  check("bulk path-ref: both succeed",
        pthResp.Operations[0].status === "200" && pthResp.Operations[1].status === "201");
  check("bulk path-ref: response in request order",
        pthResp.Operations[1].bulkId === "newbie");
  var pthUserId = Array.from(pthUsers._records.keys())[0];
  check("bulk path-ref: patch received the real id, not the token",
        pthPatchedIds.length === 1 && pthPatchedIds[0] === pthUserId);

  // Backward path ref on DELETE: the created resource is removable via
  // its bulkId path token in the same request.
  var delUsers = _mkRecordingUsers();
  var delMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: delUsers, bulk: { maxOperations: 10 },
  });
  var del = await _bulkBody(delMw, [
    { method: "POST", path: "/Users", bulkId: "gone",
      data: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "gone" } },
    { method: "DELETE", path: "/Users/bulkId:gone" },
  ]);
  var delResp = JSON.parse(del.res._body());
  check("bulk path-ref delete: both succeed",
        delResp.Operations[0].status === "201" && delResp.Operations[1].status === "204");
  check("bulk path-ref delete: record removed", delUsers._records.size === 0);

  // Undeclared path ref: fails per-op invalidValue, adapter never called.
  var updUsers = _mkRecordingUsers();
  var updMw = b.middleware.scimServer({
    basePath: "/scim/v2", users: updUsers, bulk: { maxOperations: 10 },
  });
  var upd = await _bulkBody(updMw, [
    { method: "DELETE", path: "/Users/bulkId:phantom" },
  ]);
  var updResp = JSON.parse(upd.res._body());
  check("bulk path-ref undeclared: fails 400 invalidValue",
        updResp.Operations[0].status === "400" &&
        updResp.Operations[0].response.scimType === "invalidValue");
  check("bulk path-ref undeclared: adapter untouched",
        updUsers._received.length === 0 && updUsers._records.size === 0);

  // --- maxPageSize garbage throws at create() (entry-point tier).
  var threwPage = false;
  try { b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), maxPageSize: "lots" }); }
  catch (e) { threwPage = /bad-max-page-size/.test(e.code || ""); }
  check("maxPageSize garbage refused at create()", threwPage);

  var threwPage2 = false;
  try { b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), maxPageSize: -3 }); }
  catch (e) { threwPage2 = /bad-max-page-size/.test(e.code || ""); }
  check("maxPageSize negative refused at create()", threwPage2);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
             function (e) { process.exitCode = 1; throw e; });
}
