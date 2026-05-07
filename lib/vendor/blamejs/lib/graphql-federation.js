"use strict";
/**
 * GraphQL Federation _service.sdl trust-boundary guard.
 *
 * Apollo Federation subgraphs expose the schema via _service.sdl
 * which is independent of the introspection toggle — operators who
 * disable introspection in production still leak the full SDL.
 *
 * Public API:
 *   graphqlFederation.guardSdl(opts) -> middleware
 *   graphqlFederation.queryProbesSdl(query) -> bool
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
