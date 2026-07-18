// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.middleware.scimServer — SCIM 2.0 server middleware.

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var SCIM_USER     = "urn:ietf:params:scim:schemas:core:2.0:User";
var SCIM_GROUP    = "urn:ietf:params:scim:schemas:core:2.0:Group";
var SCIM_LIST     = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
var SCIM_BULK_REQ = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

// Build a streaming (EventEmitter) request that emits its whole body as a
// single chunk + `end` on the next tick — this drives the collectStream
// read path in _readJsonBody / _readBulkBody (the branch taken when the
// framework has NOT already buffered req.body). Reuses the canonical
// b.testing.bodyReq helper and re-targets its URL for SCIM routing.
function _streamReq(method, url, bodyStr) {
  var req = b.testing.bodyReq(method, {}, bodyStr);
  req.url = url;
  return req;
}

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
  await _runBearerAuthTests();
  await _runSingletonCrudTests();
  await _runFilterParsingTests();
  await _runConfigAndMetadataTests();
  await _runBulkErrorBranchTests();
  await _runBulkBodyShapeTests();
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

// Bearer authentication gate (RFC 7644 §2 / RFC 6750). The bearer
// callback is the single authorization seam; every failure mode must
// fail CLOSED — no request reaches an adapter without a resolved actor.
async function _runBearerAuthTests() {
  var users = _mkUsers();
  var bearerCalls = [];
  var mw = b.middleware.scimServer({
    basePath: "/scim/v2",
    users:    users,
    bearer:   async function (token) {
      bearerCalls.push(token);
      if (token === "good") return { id: "admin-1", token: token };
      if (token === "boom") throw new Error("token introspection endpoint down");
      return null;   // any other token → unauthorized
    },
  });

  // Discovery endpoints are served BEFORE the bearer gate — reachable
  // without a token so clients can bootstrap.
  var pub = await _drive(mw, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} });
  check("bearer: SPC served without a token", pub.res._sc() === 200);

  // No Authorization header → 401 with a Bearer challenge.
  var noAuth = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: {} });
  check("bearer: missing header → 401",           noAuth.res._sc() === 401);
  check("bearer: missing header → Bearer challenge", noAuth.res._hdrs["www-authenticate"] === "Bearer");
  check("bearer: missing header → detail",         JSON.parse(noAuth.res._body()).detail === "Missing Bearer token");

  // A non-Bearer scheme is rejected the same way (regex miss).
  var basic = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: { authorization: "Basic dXNlcjpwYXNz" } });
  check("bearer: non-Bearer scheme → 401 Missing",
        basic.res._sc() === 401 && JSON.parse(basic.res._body()).detail === "Missing Bearer token");

  // Oversized Authorization header (>= 8 KiB) is refused by the length
  // cap before the regex ever runs, and the callback is NOT invoked.
  var before = bearerCalls.length;
  var big = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: { authorization: "Bearer " + "a".repeat(8300) } });
  check("bearer: oversized header → 401",       big.res._sc() === 401);
  check("bearer: oversized header skips callback", bearerCalls.length === before);

  // Well-formed token the callback rejects (returns falsy) → 401 with an
  // invalid_token challenge.
  var unk = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: { authorization: "Bearer nope" } });
  check("bearer: rejected token → 401",            unk.res._sc() === 401);
  check("bearer: rejected token → invalid_token",  /invalid_token/.test(unk.res._hdrs["www-authenticate"] || ""));
  check("bearer: rejected token → detail",         JSON.parse(unk.res._body()).detail === "Bearer token rejected");

  // The callback THROWS — the catch must swallow and leave actor null so
  // the request fails closed (an introspection outage never authorizes).
  var thrown = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: { authorization: "Bearer boom" } });
  check("bearer: callback throw → fail-closed 401", thrown.res._sc() === 401);
  check("bearer: callback throw → invalid_token",   /invalid_token/.test(thrown.res._hdrs["www-authenticate"] || ""));

  // Accepted token → the resolved actor is threaded into the adapter ctx.
  var seenActor = [];
  users.list = async function (q, ctx) { seenActor.push(ctx && ctx.actor); return { totalResults: 0, Resources: [] }; };
  var ok = await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: { authorization: "Bearer good" } });
  check("bearer: accepted token → 200",       ok.res._sc() === 200);
  check("bearer: actor threaded into adapter", seenActor.length === 1 && seenActor[0] && seenActor[0].id === "admin-1");
}

// The singleton resource surface: GET (list + by-id), POST, PUT, PATCH,
// DELETE, plus the error/defensive branches around each.
async function _runSingletonCrudTests() {
  var users = _mkUsers();
  var mw = b.middleware.scimServer({ basePath: "/scim/v2", users: users });

  // POST create (pre-buffered object body).
  var created = await _drive(mw, { method: "POST", url: "/scim/v2/Users", headers: {},
    body: { schemas: [SCIM_USER], userName: "alice" } });
  check("crud: POST → 201", created.res._sc() === 201);
  var uid = JSON.parse(created.res._body()).id;
  check("crud: POST returns created id", typeof uid === "string");

  // POST missing the required schema → 400 (routed through middleware
  // .catch, exercising the err.statusCode branch).
  var noSchema = await _drive(mw, { method: "POST", url: "/scim/v2/Users", headers: {}, body: { userName: "x" } });
  check("crud: POST missing schema → 400",       noSchema.res._sc() === 400);
  check("crud: POST missing schema → invalidValue", JSON.parse(noSchema.res._body()).scimType === "invalidValue");

  // POST whose body parses to a NON-object scalar → 400 (the assertSchema
  // body-shape guard, distinct from the schemas-array check).
  var scalar = await _drive(mw, { method: "POST", url: "/scim/v2/Users", headers: {}, body: Buffer.from('"scalar"') });
  check("crud: POST non-object body → 400", scalar.res._sc() === 400);

  // Streaming POST body (no pre-buffered req.body) → collectStream path.
  var streamed = await _drive(mw, _streamReq("POST", "/scim/v2/Users",
    JSON.stringify({ schemas: [SCIM_USER], userName: "streamed" })));
  check("crud: streaming POST body → 201", streamed.res._sc() === 201);

  // GET by id — found.
  var got = await _drive(mw, { method: "GET", url: "/scim/v2/Users/" + uid, headers: {} });
  check("crud: GET by id found → 200", got.res._sc() === 200 && JSON.parse(got.res._body()).id === uid);

  // GET by id — missing → 404 notFound.
  var missing = await _drive(mw, { method: "GET", url: "/scim/v2/Users/does-not-exist", headers: {} });
  check("crud: GET by id missing → 404",
        missing.res._sc() === 404 && JSON.parse(missing.res._body()).scimType === "notFound");

  // PUT replace.
  var put = await _drive(mw, { method: "PUT", url: "/scim/v2/Users/" + uid, headers: {},
    body: { schemas: [SCIM_USER], userName: "alice-2" } });
  check("crud: PUT → 200", put.res._sc() === 200 && JSON.parse(put.res._body()).userName === "alice-2");

  // PUT missing schema → 400.
  var putNoSchema = await _drive(mw, { method: "PUT", url: "/scim/v2/Users/" + uid, headers: {}, body: { userName: "nope" } });
  check("crud: PUT missing schema → 400", putNoSchema.res._sc() === 400);

  // PATCH with valid Operations.
  var patch = await _drive(mw, { method: "PATCH", url: "/scim/v2/Users/" + uid, headers: {},
    body: { Operations: [{ op: "replace", path: "active", value: false }] } });
  check("crud: PATCH → 200", patch.res._sc() === 200);

  // PATCH without Operations → 400 invalidValue.
  var patchEmpty = await _drive(mw, { method: "PATCH", url: "/scim/v2/Users/" + uid, headers: {}, body: {} });
  check("crud: PATCH no Operations → 400",
        patchEmpty.res._sc() === 400 && JSON.parse(patchEmpty.res._body()).scimType === "invalidValue");

  // PATCH op missing the 'op' verb → 400.
  var patchBadOp = await _drive(mw, { method: "PATCH", url: "/scim/v2/Users/" + uid, headers: {},
    body: { Operations: [{ path: "active", value: 1 }] } });
  check("crud: PATCH op missing verb → 400", patchBadOp.res._sc() === 400);

  // PATCH op with an unsupported verb → 400.
  var patchBadVerb = await _drive(mw, { method: "PATCH", url: "/scim/v2/Users/" + uid, headers: {},
    body: { Operations: [{ op: "frobnicate", path: "active" }] } });
  check("crud: PATCH invalid verb → 400", patchBadVerb.res._sc() === 400);

  // DELETE.
  var del = await _drive(mw, { method: "DELETE", url: "/scim/v2/Users/" + uid, headers: {} });
  check("crud: DELETE → 204",         del.res._sc() === 204);
  check("crud: DELETE removed record", users._records.get(uid) === undefined);

  // An unsupported method on an existing id → 405 noTarget.
  var opt = await _drive(mw, { method: "OPTIONS", url: "/scim/v2/Users/" + uid, headers: {} });
  check("crud: unsupported method → 405",
        opt.res._sc() === 405 && JSON.parse(opt.res._body()).scimType === "noTarget");

  // A resource path whose adapter isn't configured → 404 "not configured".
  var g404 = await _drive(mw, { method: "GET", url: "/scim/v2/Groups", headers: {} });
  check("crud: unconfigured /Groups → 404", g404.res._sc() === 404);

  // An adapter rejection (no statusCode) propagates to the middleware
  // .catch → generic 500.
  var boomUsers = _mkUsers();
  boomUsers.read = async function () { throw new Error("db exploded"); };
  var boomMw = b.middleware.scimServer({ basePath: "/scim/v2", users: boomUsers });
  var boom = await _drive(boomMw, { method: "GET", url: "/scim/v2/Users/anything", headers: {} });
  check("crud: adapter rejection → 500 via catch", boom.res._sc() === 500);

  // GET list — pagination + attribute selection threaded to the adapter.
  var listUsers = _mkUsers();
  var listSeen = null;
  listUsers.list = async function (q) { listSeen = q; return { totalResults: 3, Resources: [{ id: "u-1" }] }; };
  var listMw = b.middleware.scimServer({ basePath: "/scim/v2", users: listUsers });
  var list = await _drive(listMw, { method: "GET",
    url: "/scim/v2/Users?count=5&startIndex=2&sortBy=userName&sortOrder=descending&attributes=userName,active&excludedAttributes=password",
    headers: {} });
  check("crud: GET list → 200 ListResponse",
        list.res._sc() === 200 && JSON.parse(list.res._body()).schemas.indexOf(SCIM_LIST) !== -1);
  check("crud: list count parsed",              listSeen && listSeen.count === 5);
  check("crud: list startIndex parsed",         listSeen.startIndex === 2);
  check("crud: list sortBy/sortOrder threaded", listSeen.sortBy === "userName" && listSeen.sortOrder === "descending");
  check("crud: list attributes split",          Array.isArray(listSeen.attributes) && listSeen.attributes.length === 2);
  check("crud: list excludedAttributes split",  Array.isArray(listSeen.excludedAttributes) && listSeen.excludedAttributes[0] === "password");
  check("crud: list itemsPerPage from Resources", JSON.parse(list.res._body()).itemsPerPage === 1);

  // count over maxPageSize is clamped down to the configured cap.
  var capUsers = _mkUsers();
  var capSeen = null;
  capUsers.list = async function (q) { capSeen = q; return { totalResults: 0, Resources: [] }; };
  var capMw = b.middleware.scimServer({ basePath: "/scim/v2", users: capUsers, maxPageSize: 25 });
  await _drive(capMw, { method: "GET", url: "/scim/v2/Users?count=9999", headers: {} });
  check("crud: count clamped to maxPageSize", capSeen && capSeen.count === 25);
}

// RFC 7644 §3.4.2.2 — filter grammar parsing surfaced through the GET
// list query string (the real consumer path an IdP drives).
async function _runFilterParsingTests() {
  var users = _mkUsers();
  var mw = b.middleware.scimServer({ basePath: "/scim/v2", users: users });
  var captured = [];
  users.list = async function (q) { captured.push(q.filter); return { totalResults: 0, Resources: [] }; };

  async function listWith(rawFilter) {
    captured = [];
    await _drive(mw, { method: "GET", url: "/scim/v2/Users?filter=" + encodeURIComponent(rawFilter), headers: {} });
    return captured[0];
  }

  var pr = await listWith("title pr");
  check("filter: presence op yields no value",
        pr && pr.op === "pr" && pr.attribute === "title" && pr.value === undefined);

  var quoted = await listWith('familyName eq "O\'Brien"');
  check("filter: quoted value is unwrapped", quoted && quoted.value === "O'Brien");

  var esc = await listWith('displayName eq "a\\"b"');
  check("filter: escaped inner quote decoded", esc && esc.value === 'a"b');

  var garbage = await listWith("this is not a filter");
  check("filter: unparseable filter kept as raw",
        garbage && typeof garbage.raw === "string" && garbage.attribute === undefined);

  captured = [];
  await _drive(mw, { method: "GET", url: "/scim/v2/Users", headers: {} });
  check("filter: absent filter → null", captured[0] === null);

  // A query pair with malformed percent-encoding is skipped by the
  // decode guard rather than crashing the request.
  var badPct = await _drive(mw, { method: "GET", url: "/scim/v2/Users?x=%ZZ&count=3", headers: {} });
  check("filter: malformed percent-encoding tolerated", badPct.res._sc() === 200);
}

// Config-time option handling (basePath/bulk/maxPageSize defaults +
// refusals) and the read-only metadata surfaces.
async function _runConfigAndMetadataTests() {
  // basePath defaults when omitted.
  var dflt = b.middleware.scimServer({ users: _mkUsers() });
  check("config: basePath defaults to /scim/v2", dflt.basePath === "/scim/v2");

  // bulk:null is treated exactly like omitted — disabled.
  var nullBulk = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: null });
  var nbSpc = await _drive(nullBulk, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} });
  check("config: bulk:null → SPC supported=false", JSON.parse(nbSpc.res._body()).bulk.supported === false);

  // A non-object bulk value is refused at construction (config-time tier).
  var threwBulk = false;
  try { b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: "yes" }); }
  catch (e) { threwBulk = /bad-bulk\b/.test(e.code || ""); }
  check("config: non-object bulk refused", threwBulk);

  // bulk:{} takes the documented defaults (maxOperations 1000, 1 MiB).
  var defBulk = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: {} });
  var dbSpc = JSON.parse((await _drive(defBulk, { method: "GET", url: "/scim/v2/ServiceProviderConfig", headers: {} })).res._body());
  check("config: bulk:{} default maxOperations",  dbSpc.bulk.maxOperations === 1000);
  check("config: bulk:{} default maxPayloadSize", dbSpc.bulk.maxPayloadSize === 1048576);

  // ResourceTypes advertises Group only when a groups adapter is wired.
  var withGroups = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), groups: _mkGroups() });
  var rt = JSON.parse((await _drive(withGroups, { method: "GET", url: "/scim/v2/ResourceTypes", headers: {} })).res._body());
  var ids = rt.map(function (r) { return r.id; });
  check("config: ResourceTypes includes Group when configured",
        ids.indexOf("Group") !== -1 && ids.indexOf("User") !== -1);

  // A request to the bare basePath (no resource segment) → 404.
  var bareMw = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers() });
  var bare = await _drive(bareMw, { method: "GET", url: "/scim/v2", headers: {} });
  check("config: bare basePath → 404", bare.res._sc() === 404);
}

// RFC 7644 §3.7 — per-operation error branches inside a /Bulk batch. A
// single failing operation is isolated to its own result entry; the
// batch envelope stays 200.
async function _runBulkErrorBranchTests() {
  var mw = b.middleware.scimServer({
    basePath: "/scim/v2", users: _mkUsers(), groups: _mkGroups(), bulk: { maxOperations: 10 },
  });

  // /Bulk with a non-POST method → 405 noTarget.
  var getBulk = await _drive(mw, { method: "GET", url: "/scim/v2/Bulk", headers: {} });
  check("bulk err: GET /Bulk → 405",          getBulk.res._sc() === 405);
  check("bulk err: GET /Bulk → noTarget",     JSON.parse(getBulk.res._body()).scimType === "noTarget");

  // BulkRequest with a wrong schemas array → 400 invalidValue.
  var badSchemas = await _drive(mw, { method: "POST", url: "/scim/v2/Bulk", headers: {},
    body: { schemas: ["urn:wrong"], Operations: [] } });
  check("bulk err: wrong schemas → 400",
        badSchemas.res._sc() === 400 && JSON.parse(badSchemas.res._body()).scimType === "invalidValue");

  // BulkRequest whose Operations is not an array → 400 invalidValue.
  var opsNotArray = await _drive(mw, { method: "POST", url: "/scim/v2/Bulk", headers: {},
    body: { schemas: [SCIM_BULK_REQ], Operations: "nope" } });
  check("bulk err: Operations not an array → 400", opsNotArray.res._sc() === 400);

  // Assorted per-operation failures in one batch.
  var perOp = await _bulkBody(mw, [
    { path: "/Users", bulkId: "nomethod", data: { schemas: [SCIM_USER], userName: "x" } },   // missing method
    { method: "GET", path: "/Users/u-1" },                                                    // unsupported method
    { method: "POST", path: "/Widgets", bulkId: "badpath", data: { schemas: [SCIM_USER], userName: "y" } }, // unparseable path
    { method: "PUT", path: "/Users" },                                                        // PUT without an id
    { method: "POST", path: "/Groups", bulkId: "wschema", data: { displayName: "no-schema" } }, // POST bulkId, missing schema
  ]);
  var perOpResp = JSON.parse(perOp.res._body());
  check("bulk err: batch envelope stays 200", perOp.res._sc() === 200);
  check("bulk err: missing method → invalidSyntax 400",
        perOpResp.Operations[0].status === "400" && perOpResp.Operations[0].response.scimType === "invalidSyntax");
  check("bulk err: unsupported method → 400 invalidValue",
        perOpResp.Operations[1].status === "400" && perOpResp.Operations[1].response.scimType === "invalidValue");
  check("bulk err: unparseable path → 400", perOpResp.Operations[2].status === "400");
  check("bulk err: PUT without id → 400",   perOpResp.Operations[3].status === "400");
  check("bulk err: POST bulkId missing schema → 400", perOpResp.Operations[4].status === "400");

  // A bulk op targeting a resource with no configured adapter → per-op 404.
  var usersOnly = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: 5 } });
  var noGroup = await _bulkBody(usersOnly, [
    { method: "POST", path: "/Groups", bulkId: "g", data: { schemas: [SCIM_GROUP], displayName: "g" } },
  ]);
  check("bulk err: unconfigured resource → per-op 404",
        JSON.parse(noGroup.res._body()).Operations[0].status === "404");

  // An adapter that throws a PLAIN Error (no statusCode/scimType) → the
  // op maps to a 500 with no scimType.
  var plainErrUsers = _mkUsers();
  plainErrUsers.update = async function () { throw new Error("adapter blew up"); };
  var seed = await plainErrUsers.create({ userName: "seed" });
  var plainMw = b.middleware.scimServer({ basePath: "/scim/v2", users: plainErrUsers, bulk: { maxOperations: 5 } });
  var plain = await _bulkBody(plainMw, [
    { method: "PUT", path: "/Users/" + seed.id, data: { schemas: [SCIM_USER], userName: "x" } },
  ]);
  var plainOp = JSON.parse(plain.res._body()).Operations[0];
  check("bulk err: plain adapter error → 500",      plainOp.status === "500");
  check("bulk err: plain adapter error omits scimType", plainOp.response.scimType === undefined);

  // A creating op that "succeeds" but returns no id cannot satisfy a
  // reference; the dependent op fails 400 and no literal token is ever
  // handed to the adapter.
  var noIdUsers = {
    _received: [],
    async create(rec) { this._received.push(rec); return { meta: { resourceType: "User" } }; }, // no id assigned
    async read()  { return null; },
    async update(id, r) { return r; },
    async patch() { return {}; },
    async remove() { /* no-op */ },
    async list()  { return { totalResults: 0, Resources: [] }; },
  };
  var noIdGroups = _mkRecordingGroups();
  var noIdMw = b.middleware.scimServer({ basePath: "/scim/v2", users: noIdUsers, groups: noIdGroups, bulk: { maxOperations: 5 } });
  var noId = await _bulkBody(noIdMw, [
    { method: "POST", path: "/Users", bulkId: "x", data: { schemas: [SCIM_USER], userName: "x" } },
    { method: "POST", path: "/Groups", bulkId: "g",
      data: { schemas: [SCIM_GROUP], displayName: "g", members: [{ value: "bulkId:x" }] } },
  ]);
  var noIdResp = JSON.parse(noId.res._body());
  check("bulk err: no-id creator still 201",       noIdResp.Operations[0].status === "201");
  check("bulk err: dependent on no-id creator → 400", noIdResp.Operations[1].status === "400");
  check("bulk err: no-id group never persisted",   noIdGroups._records.size === 0);
  check("bulk err: no-id group adapter never saw a token",
        !noIdGroups._received.some(_containsBulkIdToken));
}

// The three ways a /Bulk body reaches _readBulkBody: a pre-buffered
// Buffer, a stream, and a stream that overflows maxPayloadSize.
async function _runBulkBodyShapeTests() {
  var bulkJson = JSON.stringify({
    schemas:    [SCIM_BULK_REQ],
    Operations: [{ method: "POST", path: "/Users", bulkId: "a", data: { schemas: [SCIM_USER], userName: "a" } }],
  });

  // req.body already a Buffer → parsed and executed.
  var bufMw = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: 5 } });
  var buf = await _drive(bufMw, { method: "POST", url: "/scim/v2/Bulk", headers: {}, body: Buffer.from(bulkJson) });
  check("bulk body: Buffer body parsed + run", JSON.parse(buf.res._body()).Operations[0].status === "201");

  // Streaming body (no req.body) → collectStream path.
  var streamMw = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: 5 } });
  var stream = await _drive(streamMw, _streamReq("POST", "/scim/v2/Bulk", bulkJson));
  check("bulk body: streamed body parsed + run", JSON.parse(stream.res._body()).Operations[0].status === "201");

  // Streamed body larger than maxPayloadSize → 413 tooLarge, rejected
  // before parse.
  var tinyMw = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: 5, maxPayloadSize: 64 } });
  var over = await _drive(tinyMw, _streamReq("POST", "/scim/v2/Bulk", bulkJson));   // bulkJson > 64 bytes
  check("bulk body: oversize stream → 413",       over.res._sc() === 413);
  check("bulk body: oversize stream → tooLarge",  JSON.parse(over.res._body()).scimType === "tooLarge");

  // A body that fails to PARSE (not a size overflow) is re-thrown and
  // surfaces as a generic 500 through the middleware .catch — distinct
  // from the tooLarge path.
  var badJsonMw = b.middleware.scimServer({ basePath: "/scim/v2", users: _mkUsers(), bulk: { maxOperations: 5 } });
  var badJson = await _drive(badJsonMw, { method: "POST", url: "/scim/v2/Bulk", headers: {}, body: Buffer.from("{ not valid json") });
  check("bulk body: unparseable JSON → 500", badJson.res._sc() === 500);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
             function (e) { process.exitCode = 1; throw e; });
}
