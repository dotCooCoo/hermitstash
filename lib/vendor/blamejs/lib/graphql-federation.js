"use strict";
/**
 * @module b.graphqlFederation
 * @nav    AI
 * @title  GraphQL Federation
 *
 * @intro
 *   GraphQL federation gateway with SDL trust boundary, sub-graph
 *   health, subgraph SDL signing, query plan caps.
 *
 *   Apollo Federation subgraphs expose the schema via the
 *   `_service { sdl }` query and `_entities` resolver — independent of
 *   the introspection toggle. Operators who disable introspection in
 *   production still leak the full SDL through these federation
 *   probes. The guard refuses such queries unless they carry a
 *   shared-secret router token (timing-safe-compared, 32-char
 *   minimum), with optional nonce-store replay protection so a
 *   captured router token can't be replayed across requests.
 *
 * @card
 *   GraphQL federation gateway with SDL trust boundary, sub-graph health, subgraph SDL signing, query plan caps.
 */

var crypto = require("crypto");
var C = require("./constants");
var nb = require("./numeric-bounds");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var requestHelpers = require("./request-helpers");
var audit = require("./audit");
var { GraphqlFederationError } = require("./framework-error");

var SDL_PROBE_MAX = C.BYTES.kib(64);
var ROUTER_TOKEN_MIN_LEN = 32;                                                              // allow:raw-byte-literal — string-length floor for token entropy, not bytes
var NONCE_MIN_LEN = 16;                                                                     // allow:raw-byte-literal — string-length floor for nonce entropy, not bytes
var NONCE_MAX_LEN = 256;                                                                    // allow:raw-byte-literal — string-length cap, not bytes
var NONCE_PREVIEW_LEN = 8;                                                                  // allow:raw-byte-literal — log-preview slice length, not bytes
var SDL_PROBE_RE = /(^|[\s,{])_service\b|_entities\b/;

/**
 * @primitive b.graphqlFederation.queryProbesSdl
 * @signature b.graphqlFederation.queryProbesSdl(query)
 * @since     0.7.68
 * @related   b.graphqlFederation.guardSdl
 *
 * Cheap textual probe — does the GraphQL query reference `_service`
 * or `_entities`? Returns `true` for anything that matches the
 * federation-SDL detector after a 64 KiB length bound, `false`
 * otherwise. Used by `guardSdl` to skip the auth gate for non-
 * federation queries; operator-callable so a custom middleware can
 * apply the same gate to a non-HTTP transport (queue worker, RPC).
 *
 * @example
 *   b.graphqlFederation.queryProbesSdl("query { _service { sdl } }");
 *   // → true
 *
 *   b.graphqlFederation.queryProbesSdl("query { user(id: 1) { name } }");
 *   // → false
 */
function queryProbesSdl(query) {
  if (typeof query !== "string") return false;
  if (query.length > SDL_PROBE_MAX) return false;                                        // length-bound before regex test
  return SDL_PROBE_RE.test(query);
}

function _readBearer(req) {
  var h = req.headers && req.headers.authorization;
  if (typeof h !== "string") return null;
  if (h.length > C.BYTES.kib(8)) return null;
  var m = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/.exec(h.trim());
  return m ? m[1] : null;
}

function _timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  var ab = Buffer.from(a, "utf8");
  var bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function _readBody(req, errorClass) {
  if (req.body !== undefined && req.body !== null) {
    return Promise.resolve(req.body);
  }
  var cap = C.BYTES.mib(1);
  return new Promise(function (resolve, reject) {
    var collector = safeBuffer.boundedChunkCollector({ maxBytes: cap });
    req.on("data", function (chunk) {
      try { collector.push(chunk); }
      catch (_e) {
        req.destroy();
        reject(errorClass.factory("BODY_TOO_LARGE",
          "graphqlFederation: body exceeds " + cap + " bytes"));
      }
    });
    req.on("end",  function () { resolve(collector.result().toString("utf8")); });
    req.on("error", reject);
  });
}

/**
 * @primitive b.graphqlFederation.guardSdl
 * @signature b.graphqlFederation.guardSdl(opts)
 * @since     0.7.68
 * @related   b.graphqlFederation.queryProbesSdl
 *
 * Build the federation-SDL trust-boundary middleware. Reads the
 * GraphQL query from the JSON body (capped at 1 MiB), passes
 * non-federation queries straight through, and refuses
 * `_service { sdl }` / `_entities` queries with HTTP 401 unless the
 * request carries a `Bearer <routerToken>` (timing-safe compare,
 * 32-char minimum) — or `publicSchemaOk:true` is explicitly set.
 * Optional `nonceStore` keyed off `x-apollographql-router-nonce`
 * blocks replay of a captured token across requests; default TTL is
 * 5 minutes. Returns a `(req, res, next)` middleware function.
 *
 * @opts
 *   publicSchemaOk:   boolean,                                       // default false — explicit override to publish the SDL
 *   routerToken:      string,                                        // required unless publicSchemaOk; 32+ chars
 *   nonceStore:       { has(nonce): bool, remember(nonce, ttlMs) },  // optional — replay protection
 *   nonceTtlMs:       number,                                        // default 5 minutes
 *   errorClass:       Function,                                      // default GraphqlFederationError
 *   audit:            boolean,                                       // default true
 *
 * @example
 *   var guard = b.graphqlFederation.guardSdl({
 *     routerToken: "router-shared-secret-thirty-two-chars",
 *   });
 *   typeof guard;
 *   // → "function"
 */
function guardSdl(opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || GraphqlFederationError;
  var publicSchemaOk = opts.publicSchemaOk === true;
  var routerToken = typeof opts.routerToken === "string" ? opts.routerToken : null;
  if (!publicSchemaOk && (!routerToken || routerToken.length < ROUTER_TOKEN_MIN_LEN)) {
    throw errorClass.factory("BAD_OPTS",
      "graphqlFederation.guardSdl: routerToken (32+ char) required unless publicSchemaOk=true");
  }
  var nonceStore = opts.nonceStore && typeof opts.nonceStore.has === "function" &&
                   typeof opts.nonceStore.remember === "function" ? opts.nonceStore : null;
  nb.requirePositiveFiniteIntIfPresent(opts.nonceTtlMs, "graphqlFederation.guardSdl: opts.nonceTtlMs", errorClass, "BAD_TTL");
  var nonceTtlMs = opts.nonceTtlMs || C.TIME.minutes(5);
  var auditOn = opts.audit !== false;

  function _emitDenied(req, reason, metadata) {
    if (!auditOn) return;
    audit.safeEmit({
      action:   "graphqlfederation.sdl_refused",
      outcome:  "denied",
      reason:   reason,
      metadata: Object.assign({
        ip:   requestHelpers.clientIp(req),
        path: req && req.url,
      }, metadata || {}),
    });
  }

  function _refuse(res, status, message) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Content-Type", "application/json");
    }
    res.statusCode = status;
    res.end(JSON.stringify({ errors: [{ message: message }] }));
  }

  return function graphqlFedGuard(req, res, next) {
    Promise.resolve().then(function () {
      return _readBody(req, errorClass).then(function (rawBody) {
        var query = null;
        try {
          var parsed = typeof rawBody === "string" ? safeJson.parse(rawBody, { maxBytes: C.BYTES.mib(1) }) : rawBody;             // allow:JSON.parse — routed via safeJson.parse
          query = parsed && typeof parsed === "object" ? parsed.query : null;
        } catch (_e) { /* not JSON; pass through */ }
        if (req.body === undefined) req.body = rawBody;

        if (!queryProbesSdl(query)) {
          if (typeof next === "function") next();
          return;
        }

        if (publicSchemaOk) {
          if (typeof next === "function") next();
          return;
        }

        var bearer = _readBearer(req);
        if (!bearer || !_timingSafeEqual(bearer, routerToken)) {
          _emitDenied(req, "missing or bad router-token", {});
          return _refuse(res, 401, "graphql federation: router token required for _service / _entities");
        }

        if (nonceStore) {
          var nonce = req.headers && req.headers["x-apollographql-router-nonce"];
          if (typeof nonce !== "string" || nonce.length < NONCE_MIN_LEN || nonce.length > NONCE_MAX_LEN) {
            _emitDenied(req, "missing nonce", {});
            return _refuse(res, 401, "graphql federation: nonce required");
          }
          return Promise.resolve(nonceStore.has(nonce)).then(function (seen) {
            if (seen) {
              _emitDenied(req, "nonce replay", { nonce: nonce.slice(0, NONCE_PREVIEW_LEN) + "..." });
              return _refuse(res, 401, "graphql federation: nonce replay");
            }
            return Promise.resolve(nonceStore.remember(nonce, nonceTtlMs)).then(function () {
              if (auditOn) {
                audit.safeEmit({
                  action:   "graphqlfederation.sdl_allowed",
                  outcome:  "success",
                  metadata: {},
                });
              }
              if (typeof next === "function") next();
            });
          });
        }
        if (auditOn) {
          audit.safeEmit({
            action:   "graphqlfederation.sdl_allowed",
            outcome:  "success",
            metadata: {},
          });
        }
        if (typeof next === "function") next();
      });
    }).catch(function (err) {
      _emitDenied(req, "guard error: " + (err && err.message), {});
      if (!res.writableEnded) _refuse(res, 500, "internal guard error");
    });
  };
}

module.exports = {
  guardSdl:        guardSdl,
  queryProbesSdl:  queryProbesSdl,
};
