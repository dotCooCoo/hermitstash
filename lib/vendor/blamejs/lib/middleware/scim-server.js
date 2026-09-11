// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var framework_error = require("../framework-error");
var numericBounds   = require("../numeric-bounds");
var pick            = require("../pick");
var validateOpts    = require("../validate-opts");
var safeJson        = require("../safe-json");
var safeBuffer      = require("../safe-buffer");
var requestHelpers  = require("../request-helpers");
var C               = require("../constants");

var H = requestHelpers.HTTP_STATUS;

var ScimServerError = framework_error.defineClass(
  "ScimServerError",
  "middleware/scim-server"
);

var SCIM_CORE_SCHEMA_USER  = "urn:ietf:params:scim:schemas:core:2.0:User";
var SCIM_CORE_SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
var SCIM_MESSAGE_ERROR        = "urn:ietf:params:scim:api:messages:2.0:Error";
var SCIM_MESSAGE_LIST         = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
var SCIM_MESSAGE_BULK_REQUEST  = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
var SCIM_MESSAGE_BULK_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

var BULK_ID_REF_RE = /^bulkId:(.+)$/;

var ALLOWED_FILTER_OPS = ["eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"];

var SCIM_FILTER_RE = /^\s*([a-zA-Z][a-zA-Z0-9._-]*)\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)(?:\s+(.+))?\s*$/;
var RESOURCE_PATH_RE = /^\/(Users|Groups)(?:\/([^/]+))?$/;
var BEARER_RE = /^Bearer\s+(\S.*)$/i;

/**
 * @primitive b.middleware.scimServer
 * @signature b.middleware.scimServer(opts)
 * @since     0.8.77
 * @related   b.auth.oauth.introspectToken
 *
 * Returns a request middleware that handles SCIM 2.0 requests
 * (RFC 7642-7644). Operator supplies CRUD callbacks per resource.
 *
 * Bulk operations (RFC 7644 §3.7) are opt-in: pass `opts.bulk` to
 * enable the `/Bulk` POST endpoint and advertise it in
 * ServiceProviderConfig. When omitted, `bulk.supported` stays `false`
 * and `/Bulk` is not routed (back-compatible default).
 *
 * @opts
 *   {
 *     basePath?:    string,
 *     users:        ScimResourceImpl,
 *     groups?:      ScimResourceImpl,
 *     bearer?:      (token) => Promise<actor>,
 *     maxPageSize?: number,   // default: 200 (config-time positive int)
 *     bulk?: {
 *       maxOperations?:  number,   // default: 1000 (config-time positive int)
 *       maxPayloadSize?: number,   // default: 1 MiB  (config-time positive int, bytes)
 *     },
 *   }
 *
 * @example
 *   var mw = b.middleware.scimServer({
 *     basePath: "/scim/v2",
 *     users:  myUserAdapter,
 *     groups: myGroupAdapter,
 *     bulk:   { maxOperations: 100 },
 *   });
 *   app.use(mw);
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.scimServer",
    ScimServerError, "middleware/scim-server/bad-opts");
  _validateResourceImpl(opts.users,  "users");
  if (opts.groups) _validateResourceImpl(opts.groups, "groups");

  var basePath    = opts.basePath || "/scim/v2";
  validateOpts.optionalPositiveInt(opts.maxPageSize, "middleware.scimServer: opts.maxPageSize",
    ScimServerError, "middleware/scim-server/bad-max-page-size");
  var maxPageSize = opts.maxPageSize || 200;
  var bearer      = opts.bearer || null;
  var bulkCfg     = _resolveBulkConfig(opts.bulk);

  function middleware(req, res, next) {
    var url = req.url.split("?")[0];
    if (url.indexOf(basePath) !== 0) { next(); return; }
    _dispatch(req, res, basePath, bearer, opts, maxPageSize, bulkCfg)
      .catch(function (err) {
        _writeScimError(res, err.statusCode || 500, err.scimType || "internal",
          (err.message || String(err)).slice(0, 500));
      });
  }

  middleware.basePath           = basePath;
  middleware.serviceProviderDoc = _serviceProviderConfig(opts);
  return middleware;
}

function _validateResourceImpl(impl, name) {
  if (!impl || typeof impl !== "object") {
    throw new ScimServerError("middleware/scim-server/no-" + name,
      "middleware.scimServer: opts." + name + " must be an object implementing { create, read, update, patch, remove, list }");
  }
  ["create", "read", "update", "patch", "remove", "list"].forEach(function (m) {
    if (typeof impl[m] !== "function") {
      throw new ScimServerError("middleware/scim-server/bad-" + name + "-impl",
        "middleware.scimServer: opts." + name + "." + m + " must be a function");
    }
  });
}

function _resolveBulkConfig(bulk) {
  if (bulk === undefined || bulk === null) return null;
  if (typeof bulk !== "object") {
    throw new ScimServerError("middleware/scim-server/bad-bulk",
      "middleware.scimServer: opts.bulk must be an object { maxOperations?, maxPayloadSize? }");
  }
  validateOpts.optionalPositiveInt(bulk.maxOperations, "middleware.scimServer: opts.bulk.maxOperations",
    ScimServerError, "middleware/scim-server/bad-bulk-max-operations");
  validateOpts.optionalPositiveInt(bulk.maxPayloadSize, "middleware.scimServer: opts.bulk.maxPayloadSize",
    ScimServerError, "middleware/scim-server/bad-bulk-max-payload-size");
  return {
    maxOperations:  bulk.maxOperations  || 1000,
    maxPayloadSize: bulk.maxPayloadSize || C.BYTES.mib(1),
  };
}

async function _dispatch(req, res, basePath, bearer, opts, maxPageSize, bulkCfg) {
  var relUrl = req.url.slice(basePath.length) || "/";
  var qIdx   = relUrl.indexOf("?");
  var path   = qIdx === -1 ? relUrl : relUrl.slice(0, qIdx);
  var query  = _parseQuery(qIdx === -1 ? "" : relUrl.slice(qIdx + 1));

  if (path === "/ServiceProviderConfig" && req.method === "GET") {
    _writeJson(res, H.OK, _serviceProviderConfig(opts)); return;
  }
  if (path === "/ResourceTypes" && req.method === "GET") {
    _writeJson(res, H.OK, _resourceTypes(opts)); return;
  }
  if (path === "/Schemas" && req.method === "GET") {
    _writeJson(res, H.OK, _schemas()); return;
  }

  var actor = null;
  if (bearer) {
    var authz = req.headers && req.headers.authorization;
    var m = authz && typeof authz === "string" && authz.length < C.BYTES.kib(8) && BEARER_RE.test(authz)    // allow:regex-no-length-cap header line bounded above
      ? authz.match(BEARER_RE) : null;
    if (!m) {
      res.writeHead(H.UNAUTHORIZED, {
        "Content-Type":     "application/scim+json",
        "WWW-Authenticate": "Bearer",
        "Cache-Control":    "no-store",
      });
      res.end(JSON.stringify({
        schemas:  [SCIM_MESSAGE_ERROR],
        status:   "401",
        detail:   "Missing Bearer token",
      }));
      return;
    }
    try { actor = await bearer(m[1]); }
    catch (_e) { actor = null; }
    if (!actor) {
      res.writeHead(H.UNAUTHORIZED, {
        "Content-Type":     "application/scim+json",
        "WWW-Authenticate": 'Bearer error="invalid_token"',
        "Cache-Control":    "no-store",
      });
      res.end(JSON.stringify({
        schemas:  [SCIM_MESSAGE_ERROR],
        status:   "401",
        detail:   "Bearer token rejected",
      }));
      return;
    }
  }

  var ctx     = { actor: actor, req: req };
  var users   = opts.users;
  var groups  = opts.groups;

  if (path === "/Bulk") {
    if (req.method !== "POST") {
      _writeScimError(res, H.METHOD_NOT_ALLOWED, "noTarget", req.method + " not allowed on /Bulk");
      return;
    }
    if (!bulkCfg) {
      _writeScimError(res, 501, "notSupported", "bulk operations are not enabled");
      return;
    }
    await _handleBulk(req, res, opts, bulkCfg, ctx);
    return;
  }

  var match = path.length < C.BYTES.kib(8) && RESOURCE_PATH_RE.test(path) ? path.match(RESOURCE_PATH_RE) : null;   // allow:regex-no-length-cap URL bounded above
  if (!match) {
    _writeScimError(res, H.NOT_FOUND, "notFound", "no SCIM resource at " + path);
    return;
  }
  var resourceType = match[1];
  var resourceId   = match[2] || null;
  var impl = resourceType === "Users" ? users : groups;
  if (!impl) {
    _writeScimError(res, 404, "notFound", "/" + resourceType + " not configured");
    return;
  }

  var body = null;
  if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
    body = await _readJsonBody(req);
  }

  if (req.method === "GET" && !resourceId) {
    var filter = _parseFilter(query.filter);
    var pageSize   = Math.min(maxPageSize, parseInt(query.count || "100", 10) || 100);
    var startIndex = Math.max(1, parseInt(query.startIndex || "1", 10) || 1);
    var listRv = await impl.list({
      filter:             filter,
      startIndex:         startIndex,
      count:              pageSize,
      sortBy:             query.sortBy || null,
      sortOrder:          query.sortOrder || null,
      attributes:         query.attributes ? query.attributes.split(",") : null,                  // allow:bare-split-on-quoted-header-token-grammar — RFC 7644 §3.9 attributes/excludedAttributes are SCIM attribute paths (URN-ish identifiers); grammar excludes DQUOTE
      excludedAttributes: query.excludedAttributes ? query.excludedAttributes.split(",") : null,    // allow:bare-split-on-quoted-header-token-grammar — same SCIM attribute-name grammar
    }, ctx);
    _writeJson(res, H.OK, {
      schemas:      [SCIM_MESSAGE_LIST],
      totalResults: listRv.totalResults,
      startIndex:   startIndex,
      itemsPerPage: listRv.Resources.length,
      Resources:    listRv.Resources,
    });
    return;
  }

  if (req.method === "GET" && resourceId) {
    var rec = await impl.read(resourceId, ctx);
    if (!rec) { _writeScimError(res, H.NOT_FOUND, "notFound", "no resource with id " + resourceId); return; }
    _writeJson(res, H.OK, rec);
    return;
  }

  if (req.method === "POST" && !resourceId) {
    _assertSchema(body, resourceType === "Users" ? SCIM_CORE_SCHEMA_USER : SCIM_CORE_SCHEMA_GROUP);
    var created = await impl.create(body, ctx);
    _writeJson(res, 201, created);
    return;
  }

  if (req.method === "PUT" && resourceId) {
    _assertSchema(body, resourceType === "Users" ? SCIM_CORE_SCHEMA_USER : SCIM_CORE_SCHEMA_GROUP);
    var updated = await impl.update(resourceId, body, ctx);
    _writeJson(res, H.OK, updated);
    return;
  }

  if (req.method === "PATCH" && resourceId) {
    if (!body || !Array.isArray(body.Operations) || body.Operations.length === 0) {
      _writeScimError(res, H.BAD_REQUEST, "invalidValue", "PATCH body must include Operations[]");
      return;
    }
    body.Operations.forEach(function (op, i) {
      if (!op || typeof op !== "object" || typeof op.op !== "string") {
        var e = new Error("Operations[" + i + "] missing op");
        e.statusCode = H.BAD_REQUEST; e.scimType = "invalidValue";
        throw e;
      }
      var verb = op.op.toLowerCase();
      if (verb !== "add" && verb !== "remove" && verb !== "replace") {
        var e2 = new Error("Operations[" + i + "].op = '" + op.op + "' not in add/remove/replace");
        e2.statusCode = H.BAD_REQUEST; e2.scimType = "invalidValue";
        throw e2;
      }
    });
    var patched = await impl.patch(resourceId, body.Operations, ctx);
    _writeJson(res, H.OK, patched);
    return;
  }

  if (req.method === "DELETE" && resourceId) {
    await impl.remove(resourceId, ctx);
    res.writeHead(H.NO_CONTENT, { "Cache-Control": "no-store" });
    res.end();
    return;
  }

  _writeScimError(res, H.METHOD_NOT_ALLOWED, "noTarget", req.method + " not allowed on " + path);
}

async function _handleBulk(req, res, opts, bulkCfg, ctx) {
  var body;
  try {
    body = await _readBulkBody(req, bulkCfg.maxPayloadSize);
  } catch (e) {
    if (e && e.code === "middleware/scim-server/bulk-too-large") {
      _writeScimError(res, H.PAYLOAD_TOO_LARGE, "tooLarge",
        "bulk payload exceeds maxPayloadSize of " + bulkCfg.maxPayloadSize + " bytes");
      return;
    }
    throw e;
  }

  if (!body || typeof body !== "object" ||
      !Array.isArray(body.schemas) ||
      body.schemas.indexOf(SCIM_MESSAGE_BULK_REQUEST) === -1) {
    _writeScimError(res, H.BAD_REQUEST, "invalidValue",
      "BulkRequest body.schemas must include '" + SCIM_MESSAGE_BULK_REQUEST + "'");
    return;
  }
  if (!Array.isArray(body.Operations)) {
    _writeScimError(res, H.BAD_REQUEST, "invalidValue", "BulkRequest must include Operations[]");
    return;
  }
  if (body.Operations.length > bulkCfg.maxOperations) {
    _writeScimError(res, H.PAYLOAD_TOO_LARGE, "tooMany",
      "bulk request has " + body.Operations.length +
      " operations, exceeding maxOperations of " + bulkCfg.maxOperations);
    return;
  }

  var failOnErrors = _parseFailOnErrors(body.failOnErrors);
  var bulkIdMap    = Object.create(null);
  var ops          = body.Operations;

  var plan = _planBulkOperations(ops);

  var results    = new Array(ops.length);
  var executed   = new Array(ops.length);
  var errorCount = 0;
  var stopped    = false;

  for (var s = 0; s < plan.order.length && !stopped; s++) {
    var idx = plan.order[s];
    var planned = plan.ops[idx];
    var outcome;

    if (planned.staticError) {
      outcome = _bulkErr(ops[idx], planned.staticError.status,
        planned.staticError.scimType, planned.staticError.detail);
    } else if (_anyDependencyFailed(planned.refs, plan, executed, bulkIdMap)) {
      outcome = _bulkErr(ops[idx], "400", "invalidValue",
        "Operations[" + idx + "] references a bulkId whose creating operation failed");
    } else {
      outcome = await _runBulkOperation(ops[idx], idx, opts, ctx, bulkIdMap);
    }

    results[idx]  = outcome.entry;
    executed[idx] = { isError: outcome.isError };
    if (outcome.isError) {
      errorCount++;
      if (failOnErrors !== null && errorCount >= failOnErrors) stopped = true;
    }
  }

  var emitted = [];
  for (var e = 0; e < results.length; e++) {
    if (results[e] !== undefined) emitted.push(results[e]);
  }

  _writeJson(res, H.OK, {
    schemas:    [SCIM_MESSAGE_BULK_RESPONSE],
    Operations: emitted,
  });
}

function _planBulkOperations(ops) {
  var declared    = Object.create(null);
  var planned     = new Array(ops.length);

  for (var i = 0; i < ops.length; i++) {
    var op = ops[i];
    var bulkId = op && typeof op.bulkId === "string" ? op.bulkId : null;
    var method = op && typeof op.method === "string" ? op.method.toUpperCase() : null;
    if (bulkId && method === "POST" && declared[bulkId] === undefined) {
      declared[bulkId] = i;
    }
    planned[i] = { refs: [], staticError: null, ownBulkId: method === "POST" ? bulkId : null };
  }

  for (var j = 0; j < ops.length; j++) {
    var refs = _collectBulkIdRefs(ops[j] && ops[j].data).concat(_pathBulkIdRefs(ops[j]));
    var depSet = [];
    for (var r = 0; r < refs.length; r++) {
      var refId = refs[r];
      var decl  = declared[refId];
      if (decl === undefined) {
        planned[j].staticError = {
          status:   "400",
          scimType: "invalidValue",
          detail:   "Operations[" + j + "] references undeclared bulkId '" + refId + "'",
        };
        depSet = [];
        break;
      }
      if (decl !== j && depSet.indexOf(decl) === -1) depSet.push(decl);
    }
    planned[j].refs = depSet;
  }

  var order = _topoOrderBulk(planned);
  return { ops: planned, order: order };
}

function _collectBulkIdRefs(value) {
  var out = [];
  _walkBulkIdRefs(value, out);
  return out;
}

function _pathBulkIdRefs(op) {
  if (!op || typeof op.path !== "string") return [];
  var out = [];
  var segs = op.path.split("/");
  for (var i = 0; i < segs.length; i++) {
    var ref = BULK_ID_REF_RE.exec(segs[i]);
    if (ref) out.push(ref[1]);
  }
  return out;
}

function _resolvePathBulkIdRefs(path, bulkIdMap) {
  var segs = path.split("/");
  for (var i = 0; i < segs.length; i++) {
    var ref = BULK_ID_REF_RE.exec(segs[i]);
    if (!ref) continue;
    var resolved = bulkIdMap[ref[1]];
    if (resolved === undefined) {
      throw new ScimServerError("middleware/scim-server/unresolved-bulkid",
        "references unresolved bulkId '" + ref[1] + "' in path");
    }
    segs[i] = resolved;
  }
  return segs.join("/");
}

function _walkBulkIdRefs(value, out) {
  if (typeof value === "string") {
    var ref = BULK_ID_REF_RE.exec(value);
    if (ref) out.push(ref[1]);
    return;
  }
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) _walkBulkIdRefs(value[i], out);
    return;
  }
  if (value && typeof value === "object") {
    var keys = Object.keys(value);
    for (var k = 0; k < keys.length; k++) {
      if (pick.isPoisonedKey(keys[k])) continue;
      _walkBulkIdRefs(value[keys[k]], out);
    }
  }
}

function _topoOrderBulk(planned) {
  var n          = planned.length;
  var visited    = new Array(n);
  for (var v = 0; v < n; v++) visited[v] = 0;
  var order      = [];
  var inCycle    = Object.create(null);

  for (var start = 0; start < n; start++) {
    if (visited[start] !== 0) continue;
    var stack = [{ node: start, edge: 0 }];
    while (stack.length > 0) {
      var top  = stack[stack.length - 1];
      var node = top.node;
      if (top.edge === 0) visited[node] = 1;
      var deps = (planned[node].staticError) ? [] : planned[node].refs;
      if (top.edge < deps.length) {
        var dep = deps[top.edge];
        top.edge++;
        if (visited[dep] === 0) {
          stack.push({ node: dep, edge: 0 });
        } else if (visited[dep] === 1) {
          var depPos = -1;
          for (var p = 0; p < stack.length; p++) {
            if (stack[p].node === dep) { depPos = p; break; }
          }
          for (var q = depPos; q >= 0 && q < stack.length; q++) {
            inCycle[stack[q].node] = true;
          }
        }
      } else {
        visited[node] = 2;
        order.push(node);
        stack.pop();
      }
    }
  }

  for (var c = 0; c < n; c++) {
    if (inCycle[c] && !planned[c].staticError) {
      planned[c].staticError = {
        status:   "409",
        scimType: "invalidValue",
        detail:   "Operations[" + c + "] is part of an unresolvable circular bulkId reference",
      };
    }
  }
  return order;
}

function _anyDependencyFailed(refs, plan, executed, bulkIdMap) {
  for (var i = 0; i < refs.length; i++) {
    var declIdx = refs[i];
    var rec = executed[declIdx];
    if (rec && rec.isError) return true;
    var declOp = plan.ops[declIdx];
    if (rec && !rec.isError && declOp.ownBulkId && bulkIdMap[declOp.ownBulkId] === undefined) {
      return true;
    }
  }
  return false;
}

function _parseFailOnErrors(value) {
  if (!numericBounds.isPositiveFiniteInt(value)) {
    return null;
  }
  return value;
}

async function _runBulkOperation(op, index, opts, ctx, bulkIdMap) {
  if (!op || typeof op !== "object" || typeof op.method !== "string") {
    return _bulkErr(op, "400", "invalidSyntax",
      "Operations[" + index + "] missing string method");
  }
  var method = op.method.toUpperCase();
  if (method !== "POST" && method !== "PUT" && method !== "PATCH" && method !== "DELETE") {
    return _bulkErr(op, "400", "invalidValue",
      "Operations[" + index + "].method '" + op.method + "' not in POST/PUT/PATCH/DELETE");
  }

  var path = op.path;
  if (typeof path === "string" && path.indexOf("bulkId:") !== -1) {
    try { path = _resolvePathBulkIdRefs(path, bulkIdMap); }
    catch (refErr) {
      return _bulkErr(op, "400", "invalidValue",
        "Operations[" + index + "] " + (refErr && refErr.message ? refErr.message : "has an unresolved bulkId reference in path"));
    }
  }
  var parsed = _parseBulkPath(path);
  if (!parsed) {
    return _bulkErr(op, "400", "invalidValue",
      "Operations[" + index + "].path '" + String(op.path) + "' is not a valid bulk path");
  }
  var impl = parsed.resourceType === "Users" ? opts.users : opts.groups;
  if (!impl) {
    return _bulkErr(op, "404", "invalidValue", "/" + parsed.resourceType + " not configured");
  }
  if (method === "POST" && !op.bulkId) {
    return _bulkErr(op, "400", "invalidValue",
      "Operations[" + index + "] POST requires a bulkId");
  }
  if (method !== "POST" && !parsed.resourceId) {
    return _bulkErr(op, "400", "invalidValue",
      "Operations[" + index + "] " + method + " requires a resource id in path");
  }

  var data = op.data;
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    try {
      data = _resolveBulkIdRefs(op.data, bulkIdMap);
    } catch (refErr) {
      return _bulkErr(op, "400", "invalidValue",
        "Operations[" + index + "] " + (refErr && refErr.message ? refErr.message : "has an unresolved bulkId reference"));
    }
  }

  try {
    if (method === "POST" || method === "PUT") {
      _assertSchema(data, parsed.resourceType === "Users" ? SCIM_CORE_SCHEMA_USER : SCIM_CORE_SCHEMA_GROUP);
    }
    if (method === "POST") {
      var created = await impl.create(data || {}, ctx);
      var newId   = created && created.id;
      if (op.bulkId && newId !== undefined && newId !== null) {
        bulkIdMap[String(op.bulkId)] = String(newId);
      }
      return _bulkOk(op, "201", _bulkLocation(parsed.resourceType, newId), created);
    }
    if (method === "PUT") {
      var replaced = await impl.update(parsed.resourceId, data || {}, ctx);
      return _bulkOk(op, "200", _bulkLocation(parsed.resourceType, parsed.resourceId), replaced);
    }
    if (method === "PATCH") {
      var ops = data && Array.isArray(data.Operations) ? data.Operations : [];
      var patched = await impl.patch(parsed.resourceId, ops, ctx);
      return _bulkOk(op, "200", _bulkLocation(parsed.resourceType, parsed.resourceId), patched);
    }
    await impl.remove(parsed.resourceId, ctx);
    return _bulkOk(op, "204", _bulkLocation(parsed.resourceType, parsed.resourceId), null);
  } catch (e) {
    var status   = e && e.statusCode ? String(e.statusCode) : "500";
    var scimType = e && e.scimType ? e.scimType : null;
    return _bulkErr(op, status, scimType, (e && e.message) ? String(e.message) : "operation failed");
  }
}

function _parseBulkPath(path) {
  if (typeof path !== "string" || path.length === 0) return null;
  var m = path.length < C.BYTES.kib(8) && RESOURCE_PATH_RE.test(path)                                          // allow:regex-no-length-cap path bounded above
    ? path.match(RESOURCE_PATH_RE) : null;
  if (!m) return null;
  return { resourceType: m[1], resourceId: m[2] || null };
}

function _resolveBulkIdRefs(value, bulkIdMap) {
  if (typeof value === "string") {
    var ref = BULK_ID_REF_RE.exec(value);
    if (ref) {
      var resolved = bulkIdMap[ref[1]];
      if (resolved === undefined) {
        throw new ScimServerError("middleware/scim-server/unresolved-bulkid",
          "references unresolved bulkId '" + ref[1] + "'");
      }
      return resolved;
    }
    return value;
  }
  if (Array.isArray(value)) {
    var arr = [];
    for (var i = 0; i < value.length; i++) arr.push(_resolveBulkIdRefs(value[i], bulkIdMap));
    return arr;
  }
  if (value && typeof value === "object") {
    var out = {};
    var keys = Object.keys(value);
    for (var k = 0; k < keys.length; k++) {
      if (pick.isPoisonedKey(keys[k])) continue;
      out[keys[k]] = _resolveBulkIdRefs(value[keys[k]], bulkIdMap);
    }
    return out;
  }
  return value;
}

function _bulkLocation(resourceType, id) {
  if (id === undefined || id === null) return undefined;
  return "/" + resourceType + "/" + String(id);
}

function _bulkOk(op, status, location, response) {
  var entry = { method: op && op.method, status: status };
  if (op && op.bulkId) entry.bulkId = op.bulkId;
  if (location) entry.location = location;
  if (response !== null && response !== undefined) entry.response = response;
  return { entry: entry, isError: false };
}

function _bulkErr(op, status, scimType, detail) {
  var errBody = { schemas: [SCIM_MESSAGE_ERROR], status: status, detail: detail };
  if (scimType) errBody.scimType = scimType;
  var entry = { method: op && op.method, status: status, response: errBody };
  if (op && op.bulkId) entry.bulkId = op.bulkId;
  return { entry: entry, isError: true };
}

function _readBulkBody(req, maxBytes) {
  if (req.body && Buffer.isBuffer(req.body)) {
    return Promise.resolve(safeJson.parse(req.body.toString("utf8"), { maxBytes: maxBytes }));
  }
  if (req.body && typeof req.body === "object") return Promise.resolve(req.body);
  return safeBuffer.collectStream(req, {
    maxBytes:   maxBytes,
    errorClass: ScimServerError,
    sizeCode:   "middleware/scim-server/bulk-too-large",
  }).then(function (buf) {
    return safeJson.parse(buf.toString("utf8"), { maxBytes: maxBytes });
  });
}

function _parseQuery(qs) {
  var out = {};
  if (!qs) return out;
  qs.split("&").forEach(function (pair) {
    var eq = pair.indexOf("=");
    var k  = eq === -1 ? pair : pair.slice(0, eq);
    var v  = eq === -1 ? ""   : pair.slice(eq + 1);
    try { out[decodeURIComponent(k)] = decodeURIComponent(v.replace(/\+/g, " ")); }
    catch (_e) { /* skip malformed */ }
  });
  return out;
}

function _parseFilter(filter) {
  if (typeof filter !== "string" || filter.length === 0) return null;
  if (!SCIM_FILTER_RE.test(filter)) return { raw: filter };
  var m = filter.match(SCIM_FILTER_RE);
  var op = m[2].toLowerCase();
  if (ALLOWED_FILTER_OPS.indexOf(op) === -1) return { raw: filter };
  var rv = { attribute: m[1], op: op, raw: filter };
  if (op === "pr") return rv;
  var v = (m[3] || "").trim();
  if (v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
    v = v.slice(1, -1).replace(/\\"/g, '"');
  }
  rv.value = v;
  return rv;
}

function _readJsonBody(req) {
  var MAX = C.BYTES.mib(1);
  if (req.body && Buffer.isBuffer(req.body)) {
    return Promise.resolve(safeJson.parse(req.body.toString("utf8"), { maxBytes: MAX }));
  }
  if (req.body && typeof req.body === "object") return Promise.resolve(req.body);
  return safeBuffer.collectStream(req, {
    maxBytes:   MAX,
    errorClass: ScimServerError,
    sizeCode:   "middleware/scim-server/body-too-large",
  }).then(function (buf) {
    return safeJson.parse(buf.toString("utf8"), { maxBytes: MAX });
  });
}

function _assertSchema(body, expectedSchema) {
  if (!body || typeof body !== "object") {
    var e = new Error("request body must be a JSON object");
    e.statusCode = H.BAD_REQUEST; e.scimType = "invalidValue"; throw e;
  }
  if (!Array.isArray(body.schemas) || body.schemas.indexOf(expectedSchema) === -1) {
    var e2 = new Error("body.schemas must include '" + expectedSchema + "'");
    e2.statusCode = H.BAD_REQUEST; e2.scimType = "invalidValue"; throw e2;
  }
}

function _writeJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type":  "application/scim+json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function _writeScimError(res, status, scimType, detail) {
  res.writeHead(status, {
    "Content-Type":  "application/scim+json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify({
    schemas:  [SCIM_MESSAGE_ERROR],
    status:   String(status),
    scimType: scimType,
    detail:   detail,
  }));
}

function _serviceProviderConfig(opts) {
  var bulkCfg = _resolveBulkConfig(opts.bulk);
  var bulk = bulkCfg
    ? { supported: true,  maxOperations: bulkCfg.maxOperations, maxPayloadSize: bulkCfg.maxPayloadSize }
    : { supported: false, maxOperations: 0, maxPayloadSize: 0 };
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    documentationUri: opts.documentationUri || "https://datatracker.ietf.org/doc/html/rfc7643",
    patch:            { supported: true },
    bulk:             bulk,
    filter:           { supported: true, maxResults: opts.maxPageSize || 200 },
    changePassword:   { supported: false },
    sort:             { supported: true },
    etag:             { supported: false },
    authenticationSchemes: [
      {
        type:        "oauthbearertoken",
        name:        "OAuth 2.0 Bearer Token",
        description: "Authentication scheme using the OAuth Bearer Token Standard",
        specUri:     "https://www.rfc-editor.org/info/rfc6750",
        primary:     true,
      },
    ],
  };
}

function _resourceTypes(opts) {
  var rv = [
    {
      schemas:  ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
      id:       "User", name: "User", endpoint: "/Users",
      description: "User resource (RFC 7643 §4.1)",
      schema:   SCIM_CORE_SCHEMA_USER,
    },
  ];
  if (opts.groups) {
    rv.push({
      schemas:  ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
      id:       "Group", name: "Group", endpoint: "/Groups",
      description: "Group resource (RFC 7643 §4.2)",
      schema:   SCIM_CORE_SCHEMA_GROUP,
    });
  }
  return rv;
}

function _schemas() {
  return [
    { id: SCIM_CORE_SCHEMA_USER,  name: "User",  description: "RFC 7643 §4.1 User resource" },
    { id: SCIM_CORE_SCHEMA_GROUP, name: "Group", description: "RFC 7643 §4.2 Group resource" },
  ];
}

module.exports = {
  create:                         create,
  ScimServerError:                ScimServerError,
  SCIM_CORE_SCHEMA_USER:          SCIM_CORE_SCHEMA_USER,
  SCIM_CORE_SCHEMA_GROUP:         SCIM_CORE_SCHEMA_GROUP,
  SCIM_MESSAGE_BULK_REQUEST:      SCIM_MESSAGE_BULK_REQUEST,
  SCIM_MESSAGE_BULK_RESPONSE:     SCIM_MESSAGE_BULK_RESPONSE,
  ALLOWED_FILTER_OPS:             ALLOWED_FILTER_OPS,
};
