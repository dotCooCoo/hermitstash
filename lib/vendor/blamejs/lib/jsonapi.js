"use strict";
/**
 * @module b.jsonApi
 * @nav    HTTP
 * @title  JSON:API
 * @order  172
 *
 * @intro
 *   JSON:API v1.1 (jsonapi.org/format/1.1/) response-shape helpers.
 *   The framework's wire-format primitives compose this so operators
 *   building JSON:API services get the right top-level shape + the
 *   right Content-Type without re-implementing the spec each time.
 *
 *   Content-Type: `application/vnd.api+json`
 *
 *   Top-level shapes:
 *     - `dataResponse(data, opts?)` — `{ data: [...] | {...}, included?, links?, meta? }`
 *     - `errorResponse(errors)`     — `{ errors: [...] }`
 *     - `linkObject(url, opts?)`    — string href OR `{ href, rel, meta }`
 *
 * @card
 *   JSON:API v1.1 response shape builders. Content-Type negotiation, top-level data/errors/included/links/meta wrappers, error-object shape per §7.
 */

var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var JsonApiError = defineClass("JsonApiError", { alwaysPermanent: true });

var CONTENT_TYPE = "application/vnd.api+json";

/**
 * @primitive b.jsonApi.dataResponse
 * @signature b.jsonApi.dataResponse(data, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Build a JSON:API v1.1 success response. `data` can be a Resource
 * Object, an array of Resource Objects, or null (for single-resource
 * 404 / empty-collection responses). Each Resource Object must carry
 * `type` + `id` (§7.2).
 *
 * @opts
 *   included: ResourceObject[],   // compound documents §7.7
 *   links:    object,             // top-level links §7.5
 *   meta:     object,             // non-standard top-level meta §7.4
 *   jsonapi:  object,             // jsonapi-object §7.3 (version etc.)
 *
 * @example
 *   res.setHeader("Content-Type", "application/vnd.api+json");
 *   res.end(JSON.stringify(b.jsonApi.dataResponse(
 *     { type: "articles", id: "1", attributes: { title: "Hello" } },
 *     { links: { self: "/articles/1" } }
 *   )));
 */
function dataResponse(data, opts) {
  opts = opts || {};
  validateOpts(opts, ["included", "links", "meta", "jsonapi"], "jsonApi.dataResponse");
  if (data !== null && data !== undefined) {
    if (Array.isArray(data)) {
      for (var i = 0; i < data.length; i += 1) _assertResource(data[i], i);
    } else {
      _assertResource(data, null);
    }
  }
  var out = { data: data === undefined ? null : data };
  if (opts.included) {
    if (!Array.isArray(opts.included)) {
      throw new JsonApiError("json-api/bad-included",
        "dataResponse: opts.included must be an array");
    }
    for (var j = 0; j < opts.included.length; j += 1) _assertResource(opts.included[j], j);
    out.included = opts.included;
  }
  if (opts.links)   out.links   = opts.links;
  if (opts.meta)    out.meta    = opts.meta;
  if (opts.jsonapi) out.jsonapi = opts.jsonapi;
  return out;
}

/**
 * @primitive b.jsonApi.errorResponse
 * @signature b.jsonApi.errorResponse(errors, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Build a JSON:API v1.1 error response per §7.6. Each error object
 * can carry `id` / `status` / `code` / `title` / `detail` / `source` /
 * `links` / `meta`. The framework refuses errors lacking BOTH
 * `status` and `title` (most JSON:API consumers need at least one).
 *
 * @opts
 *   meta:     object,    // optional top-level `meta` block (JSON:API §5.3)
 *   jsonapi:  object,    // optional top-level `jsonapi` member (JSON:API §5.2 — version / ext / profile)
 *   links:    object,    // optional top-level `links` (JSON:API §5.4 — self / related / pagination)
 *
 * @example
 *   res.statusCode = 422;
 *   res.end(JSON.stringify(b.jsonApi.errorResponse([
 *     { status: "422", code: "INVALID", title: "Invalid email",
 *       source: { pointer: "/data/attributes/email" } },
 *   ])));
 */
function errorResponse(errors, opts) {
  opts = opts || {};
  if (!Array.isArray(errors) || errors.length === 0) {
    throw new JsonApiError("json-api/no-errors",
      "errorResponse: errors must be a non-empty array");
  }
  var checked = errors.map(function (e, idx) {
    if (!e || typeof e !== "object") {
      throw new JsonApiError("json-api/bad-error",
        "errorResponse: errors[" + idx + "] must be an object");
    }
    if (typeof e.status !== "string" && typeof e.title !== "string") {
      throw new JsonApiError("json-api/empty-error",
        "errorResponse: errors[" + idx + "] must have at least 'status' or 'title' (string)");
    }
    return e;
  });
  var out = { errors: checked };
  if (opts.meta)    out.meta    = opts.meta;
  if (opts.jsonapi) out.jsonapi = opts.jsonapi;
  if (opts.links)   out.links   = opts.links;
  return out;
}

function _assertResource(r, idx) {
  if (!r || typeof r !== "object") {
    throw new JsonApiError("json-api/bad-resource",
      "Resource at " + (idx === null ? "<root>" : "index " + idx) + " must be an object");
  }
  if (typeof r.type !== "string" || r.type.length === 0) {
    throw new JsonApiError("json-api/missing-type",
      "Resource at " + (idx === null ? "<root>" : "index " + idx) + " missing 'type'");
  }
  // id is OPTIONAL only on client-side create requests; we don't have
  // a way to distinguish, so we accept missing id (the operator's
  // responsibility to set it for non-create paths).
}

/**
 * @primitive b.jsonApi.parseQuery
 * @signature b.jsonApi.parseQuery(queryString, opts?)
 * @since     0.10.16
 * @status    stable
 *
 * Parse a JSON:API v1.1 query string per §5 (Fetching Data). Returns
 * `{ include, fields, filter, sort, page }`:
 *   - `include` — array of relationship paths from `include=` (comma-split)
 *   - `fields[type]` — array of sparse-fieldset selectors per type
 *   - `filter` — pass-through object (spec defers filter shape to operators)
 *   - `sort` — array of `{ field, asc }` per RFC 7159-style direction
 *   - `page` — pass-through object (operator picks page-strategy)
 *
 * Refuses missing required `include` paths when opts.includeAllowlist is
 * supplied and an unrecognized path appears.
 *
 * @opts
 *   includeAllowlist:    string[],
 *   sortAllowlist:       string[],
 *   maxIncludeDepth:     number,    // default 5
 *
 * @example
 *   var q = b.jsonApi.parseQuery(req.url.split("?")[1]);
 *   q.include;         // → ["author", "comments.author"]
 *   q.fields.articles; // → ["title", "body"]
 *   q.sort;            // → [{ field: "createdAt", asc: false }]
 */
function parseQuery(queryString, opts) {
  opts = opts || {};
  if (typeof queryString !== "string") {
    throw new JsonApiError("json-api/bad-query",
      "parseQuery: queryString must be a string");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxIncludeDepth, "maxIncludeDepth",
    JsonApiError, "json-api/bad-max-include-depth");
  var maxDepth = typeof opts.maxIncludeDepth === "number" ? opts.maxIncludeDepth : 5;
  var out = { include: [], fields: {}, filter: {}, sort: [], page: {} };
  if (queryString.length === 0) return out;
  var pairs = queryString.split("&");
  for (var i = 0; i < pairs.length; i += 1) {
    var eq = pairs[i].indexOf("=");
    if (eq === -1) continue;
    var rawKey = decodeURIComponent(pairs[i].slice(0, eq));
    var rawVal = decodeURIComponent(pairs[i].slice(eq + 1));
    if (rawKey === "include") {
      out.include = rawVal.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      for (var ii = 0; ii < out.include.length; ii += 1) {
        var depth = out.include[ii].split(".").length;
        if (depth > maxDepth) {
          throw new JsonApiError("json-api/include-too-deep",
            "parseQuery: include path '" + out.include[ii] + "' exceeds maxIncludeDepth=" + maxDepth);
        }
        if (Array.isArray(opts.includeAllowlist) &&
            opts.includeAllowlist.indexOf(out.include[ii]) === -1) {
          throw new JsonApiError("json-api/include-not-allowed",
            "parseQuery: include path '" + out.include[ii] + "' not in allowlist");
        }
      }
    } else if (rawKey === "sort") {
      out.sort = rawVal.split(",").map(function (s) { return s.trim(); }).filter(Boolean).map(function (s) {
        var asc = true;
        if (s.charAt(0) === "-") { asc = false; s = s.slice(1); }
        if (Array.isArray(opts.sortAllowlist) && opts.sortAllowlist.indexOf(s) === -1) {
          throw new JsonApiError("json-api/sort-not-allowed",
            "parseQuery: sort field '" + s + "' not in allowlist");
        }
        return { field: s, asc: asc };
      });
    } else if (rawKey.indexOf("fields[") === 0 && rawKey.charAt(rawKey.length - 1) === "]") {
      var type = rawKey.slice(7, -1);                                                                 // allow:raw-byte-literal — `fields[` length
      out.fields[type] = rawVal.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    } else if (rawKey.indexOf("filter[") === 0 && rawKey.charAt(rawKey.length - 1) === "]") {
      out.filter[rawKey.slice(7, -1)] = rawVal;                                                       // allow:raw-byte-literal — `filter[` length
    } else if (rawKey.indexOf("page[") === 0 && rawKey.charAt(rawKey.length - 1) === "]") {
      out.page[rawKey.slice(5, -1)] = rawVal;                                                         // allow:raw-byte-literal — `page[` length
    }
  }
  return out;
}

module.exports = {
  dataResponse:  dataResponse,
  errorResponse: errorResponse,
  parseQuery:    parseQuery,
  CONTENT_TYPE:  CONTENT_TYPE,
  JsonApiError:  JsonApiError,
};
