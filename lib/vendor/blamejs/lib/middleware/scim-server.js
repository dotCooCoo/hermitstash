"use strict";
// SCIM 2.0 server middleware (RFC 7642 / 7643 / 7644).
// Provides /Users + /Groups + /ServiceProviderConfig + /ResourceTypes
// + /Schemas surfaces backed by operator-supplied CRUD callbacks.

var framework_error = require("../framework-error");
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
var SCIM_MESSAGE_ERROR     = "urn:ietf:params:scim:api:messages:2.0:Error";
var SCIM_MESSAGE_LIST      = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

var ALLOWED_FILTER_OPS = ["eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"];

var SCIM_FILTER_RE = /^\s*([a-zA-Z][a-zA-Z0-9._-]*)\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)(?:\s+(.+))?\s*$/;
var RESOURCE_PATH_RE = /^\/(Users|Groups)(?:\/([^/]+))?$/;
var BEARER_RE = /^Bearer\s+(.+)$/i;

/**
 * @primitive b.middleware.scimServer
 * @signature b.middleware.scimServer(opts)
 * @since     0.8.77
 * @related   b.auth.oauth.introspectToken
 *
 * Returns a request middleware that handles SCIM 2.0 requests
 * (RFC 7642-7644). Operator supplies CRUD callbacks per resource.
 *
 * @opts
 *   {
 *     basePath?:    string,
 *     users:        ScimResourceImpl,
 *     groups?:      ScimResourceImpl,
 *     bearer?:      (token) => Promise<actor>,
 *     maxPageSize?: number,
 *   }
 *
 * @example
 *   var mw = b.middleware.scimServer({
 *     basePath: "/scim/v2",
 *     users:  myUserAdapter,
 *     groups: myGroupAdapter,
 *   });
 *   app.use(mw);
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.scimServer",
    ScimServerError, "middleware/scim-server/bad-opts");
  _validateResourceImpl(opts.users,  "users");
  if (opts.groups) _validateResourceImpl(opts.groups, "groups");

  var basePath    = opts.basePath || "/scim/v2";
  var maxPageSize = opts.maxPageSize || 200;                                                                  // page-size count, not bytes
  var bearer      = opts.bearer || null;

  function middleware(req, res, next) {
    var url = req.url.split("?")[0];
    if (url.indexOf(basePath) !== 0) { next(); return; }
    _dispatch(req, res, basePath, bearer, opts, maxPageSize)
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

async function _dispatch(req, res, basePath, bearer, opts, maxPageSize) {
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
    // BEARER_RE applies to a single header line; node http caps header lines at 8 KiB.
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

  // RESOURCE_PATH_RE applies to a URL path; node http caps URL at 8 KiB.
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
      attributes:         query.attributes ? query.attributes.split(",") : null,                  // allow:bare-split-on-quoted-header — RFC 7644 §3.9 attributes/excludedAttributes are SCIM attribute paths (URN-ish identifiers); grammar excludes DQUOTE
      excludedAttributes: query.excludedAttributes ? query.excludedAttributes.split(",") : null,    // allow:bare-split-on-quoted-header — same SCIM attribute-name grammar
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
    _writeJson(res, H.CREATED, created);
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
  return safeBuffer.boundedChunkCollector(req, MAX, ScimServerError, "middleware/scim-server/body-too-large")
    .then(function (buf) {
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
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    documentationUri: opts.documentationUri || "https://datatracker.ietf.org/doc/html/rfc7643",
    patch:            { supported: true },
    bulk:             { supported: false, maxOperations: 0, maxPayloadSize: 0 },
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
  create:                 create,
  ScimServerError:        ScimServerError,
  SCIM_CORE_SCHEMA_USER:  SCIM_CORE_SCHEMA_USER,
  SCIM_CORE_SCHEMA_GROUP: SCIM_CORE_SCHEMA_GROUP,
  ALLOWED_FILTER_OPS:     ALLOWED_FILTER_OPS,
};
