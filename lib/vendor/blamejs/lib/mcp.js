"use strict";
/**
 * @module b.mcp
 * @featured true
 * @nav    AI
 * @title  Model Context Protocol
 *
 * @intro
 *   Model Context Protocol server hardening — input validation, OAuth
 *   integration per RFC 9728, scope enforcement, audit emission.
 *
 *   The guard is the secure-by-default front door for an HTTP endpoint
 *   that speaks MCP. Every default refuses; operators opt into
 *   capabilities (dynamic client registration, specific tools, specific
 *   resources) deliberately. The 2025-2026 CVE class — auth-bypass on
 *   unauthenticated tool / resource invocations (CVE-2026-33032 class)
 *   plus OAuth redirect_uri abuse (CVE-2025-6514 class) plus the
 *   confused-deputy pattern when static client IDs combine with
 *   dynamic registration — is what the guard's defaults exist to
 *   close.
 *
 *   Wire format is JSON-RPC 2.0; `parseRequest` is the envelope
 *   validator (jsonrpc version, method shape, id type, params type)
 *   and `refuse` is the matching error responder so handlers stay
 *   in the same shape the guard rejects with. OAuth redirect_uris
 *   are exact-match against an allowlist and required to be HTTPS
 *   (or localhost) per RFC 9700 §4.1.1.
 *
 * @card
 *   Model Context Protocol server hardening — input validation, OAuth integration per RFC 9728, scope enforcement, audit emission.
 */

var C = require("./constants");
var nb = require("./numeric-bounds");
var safeUrl = require("./safe-url");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var requestHelpers = require("./request-helpers");
var audit = require("./audit");
var { McpError } = require("./framework-error");

var TOOL_NAME_MAX     = 64;                                                                  // allow:raw-byte-literal — string-length cap, not bytes
var RESOURCE_NAME_MAX = 256;                                                                 // allow:raw-byte-literal — string-length cap, not bytes
var METHOD_NAME_MAX   = 256;                                                                 // allow:raw-byte-literal — string-length cap, not bytes
// JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification#error_object).
// Negative numerics by spec; mapped to HTTP status for the framework's
// HTTP-shaped reply envelope.
var JSONRPC_PARSE_ERROR     = -32700;                                                        // allow:raw-byte-literal — JSON-RPC 2.0 fixed error code / allow:raw-time-literal — not seconds
var JSONRPC_INVALID_REQUEST = -32600;                                                        // allow:raw-byte-literal — JSON-RPC 2.0 fixed error code / allow:raw-time-literal — not seconds
var JSONRPC_METHOD_NOT_FOUND= -32601;                                                        // allow:raw-byte-literal — JSON-RPC 2.0 fixed error code / allow:raw-time-literal — not seconds
var JSONRPC_INVALID_PARAMS  = -32602;                                                        // allow:raw-byte-literal — JSON-RPC 2.0 fixed error code / allow:raw-time-literal — not seconds
var JSONRPC_INTERNAL_ERROR  = -32603;                                                        // allow:raw-byte-literal — JSON-RPC 2.0 fixed error code / allow:raw-time-literal — not seconds
var JSONRPC_AUTH_REQUIRED   = -32001;                                                        // allow:raw-byte-literal — JSON-RPC server-error reserved range / allow:raw-time-literal — not seconds
var TOOL_NAME_RE     = /^[a-zA-Z][a-zA-Z0-9._-]{0,63}$/;
var RESOURCE_NAME_RE = /^[a-zA-Z][a-zA-Z0-9._/-]{0,255}$/;

/**
 * @primitive b.mcp.parseRequest
 * @signature b.mcp.parseRequest(body, opts)
 * @since     0.7.68
 * @related   b.mcp.serverGuard, b.mcp.refuse
 *
 * Validate a JSON-RPC 2.0 envelope. Accepts a raw string (parsed via
 * `b.safeJson.parse` with a 1 MiB cap) or an already-parsed object.
 * Throws an `McpError` with a code matching the violation
 * (`BAD_JSON` / `BAD_ENVELOPE` / `BAD_VERSION` / `BAD_METHOD` /
 * `BAD_ID` / `BAD_PARAMS`). Returns the parsed envelope on success.
 *
 * @opts
 *   errorClass: Function,   // default McpError; inject for custom error classes
 *
 * @example
 *   var envelope = b.mcp.parseRequest('{"jsonrpc":"2.0","method":"tools/list","id":1}', {});
 *   envelope.method;
 *   // → "tools/list"
 */
function parseRequest(body, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || McpError;
  var parsed;
  try {
    parsed = typeof body === "string" ? safeJson.parse(body, { maxBytes: C.BYTES.mib(1) }) : body;                                  // allow:JSON.parse — routed via safeJson.parse
  } catch (_e) {
    throw errorClass.factory("BAD_JSON",
      "mcp.parseRequest: body is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw errorClass.factory("BAD_ENVELOPE",
      "mcp.parseRequest: request must be a JSON-RPC object");
  }
  if (parsed.jsonrpc !== "2.0") {
    throw errorClass.factory("BAD_VERSION",
      "mcp.parseRequest: jsonrpc must be \"2.0\"");
  }
  if (typeof parsed.method !== "string" || parsed.method.length === 0 ||
      parsed.method.length > METHOD_NAME_MAX) {
    throw errorClass.factory("BAD_METHOD",
      "mcp.parseRequest: method must be a non-empty string under 256 bytes");
  }
  if (parsed.id !== undefined && parsed.id !== null &&
      typeof parsed.id !== "string" && typeof parsed.id !== "number") {
    throw errorClass.factory("BAD_ID",
      "mcp.parseRequest: id must be string, number, or null");
  }
  if (parsed.params !== undefined && parsed.params !== null &&
      typeof parsed.params !== "object") {
    throw errorClass.factory("BAD_PARAMS",
      "mcp.parseRequest: params must be object or array");
  }
  return parsed;
}

/**
 * @primitive b.mcp.refuse
 * @signature b.mcp.refuse(res, code, message, id)
 * @since     0.7.68
 * @related   b.mcp.parseRequest, b.mcp.serverGuard
 *
 * Write a JSON-RPC 2.0 error reply to `res`. The `code` is the
 * negative JSON-RPC error code (-32700 parse error, -32600 invalid
 * request, -32601 method not found, -32602 invalid params, -32603
 * internal error, -32001 auth required); HTTP status is mapped from
 * it (parse / invalid-request -> 400, method-not-found -> 404,
 * internal -> 500, default -> 400). `id` defaults to `null` when
 * undefined per the spec for unidentifiable requests.
 *
 * @example
 *   var http = require("http");
 *   var srv  = http.createServer(function (req, res) {
 *     b.mcp.refuse(res, -32601, "method not found", 7);
 *   });
 *   srv.listen(0);
 *   // → writes { jsonrpc: "2.0", error: { code: -32601, message: "method not found" }, id: 7 }
 *   srv.close();
 */
function refuse(res, code, message, id) {
  var body = JSON.stringify({
    jsonrpc: "2.0",
    error:   { code: code, message: message },
    id:      id === undefined ? null : id,
  });
  if (typeof res.setHeader === "function") {
    res.setHeader("Content-Type", "application/json");
  }
  // HTTP status mapping for the JSON-RPC error code we reply with.
  res.statusCode = code === JSONRPC_PARSE_ERROR || code === JSONRPC_INVALID_REQUEST ? 400 :  // allow:raw-byte-literal — HTTP status code (RFC 9110)
                   code === JSONRPC_METHOD_NOT_FOUND ? 404 :                                  // allow:raw-byte-literal — HTTP status code (RFC 9110)
                   code === JSONRPC_INTERNAL_ERROR ? 500 : 400;                              // allow:raw-byte-literal — HTTP status code (RFC 9110)
  res.end(body);
}

function _readBearer(req) {
  var h = req.headers && req.headers.authorization;
  if (typeof h !== "string") return null;
  if (h.length > C.BYTES.kib(8)) return null;
  var m = /^Bearer\s+([A-Za-z0-9._~+/=-]+)$/.exec(h.trim());
  return m ? m[1] : null;
}

function _readBodyBuffered(req, maxBytes, errorClass) {
  if (req.body !== undefined && req.body !== null) {
    return Promise.resolve(req.body);
  }
  return new Promise(function (resolve, reject) {
    var collector = safeBuffer.boundedChunkCollector({ maxBytes: maxBytes });
    req.on("data", function (chunk) {
      try { collector.push(chunk); }
      catch (_e) {
        req.destroy();
        reject(errorClass.factory("BODY_TOO_LARGE",
          "mcp: request body exceeds " + maxBytes + " bytes"));
      }
    });
    req.on("end",  function () { resolve(collector.result().toString("utf8")); });
    req.on("error", reject);
  });
}

function _checkRedirectUri(uri, allowlist, errorClass) {
  if (typeof uri !== "string") {
    throw errorClass.factory("BAD_REDIRECT_URI",
      "mcp: redirect_uri must be a string");
  }
  if (!Array.isArray(allowlist) || allowlist.indexOf(uri) === -1) {
    throw errorClass.factory("REDIRECT_URI_REFUSED",
      "mcp: redirect_uri not in allowlist (OAuth 2.1 / RFC 9700 sec 4.1.1)");
  }
  var parsed;
  try { parsed = safeUrl.parse(uri); }
  catch (_e) {
    throw errorClass.factory("BAD_REDIRECT_URI",
      "mcp: redirect_uri did not parse");
  }
  var isHttps = parsed.protocol === "https:";
  var isLocal = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" ||
                parsed.hostname === "::1";
  if (!isHttps && !isLocal) {
    throw errorClass.factory("INSECURE_REDIRECT_URI",
      "mcp: redirect_uri must be HTTPS (or localhost; RFC 9700 sec 4.1.1)");
  }
}

/**
 * @primitive b.mcp.serverGuard
 * @signature b.mcp.serverGuard(opts)
 * @since     0.7.68
 * @related   b.mcp.parseRequest, b.mcp.refuse, b.middleware.bearerAuth
 *
 * Build the MCP request-lifecycle middleware. Bearer-required by
 * default (operator supplies `verifyBearer` to validate the token);
 * dynamic-client-registration refused by default; redirect_uris
 * exact-match an HTTPS-or-localhost allowlist; tool / resource names
 * are shape-validated and optionally allowlist-gated; the body is
 * read through a bounded chunk collector. Every refusal emits an
 * audit event (`mcp.auth.missing-bearer` / `mcp.tool.refused` / etc.)
 * unless `audit:false`. Returns a `(req, res, next)` middleware
 * function that attaches `req.mcpRequest` + `req.mcpClaims` on
 * success.
 *
 * @opts
 *   requireBearer:           boolean,                                 // default true
 *   verifyBearer:            function,                                // (token, req) -> Promise<claims | null>
 *   redirectUriAllowlist:    Array<string>,                           // exact-match URIs
 *   allowDynamicRegister:    boolean,                                 // default false
 *   registerClientAllowlist: function,                                // (body) -> bool — required when allowDynamicRegister
 *   toolAllowlist:           Array<string>,                           // null = allow any shape-valid tool
 *   resourceAllowlist:       Array<string>,                           // null = allow any shape-valid resource
 *   maxBodyBytes:            number,                                  // default 1 MiB
 *   errorClass:              Function,                                // default McpError
 *   audit:                   boolean,                                 // default true
 *
 * @example
 *   var guard = b.mcp.serverGuard({
 *     requireBearer: true,
 *     verifyBearer:  function (token, _req) {
 *       return token === "operator-issued-bearer-token-32-chars-min" ? { sub: "ops" } : null;
 *     },
 *     toolAllowlist:     ["search.docs", "search.tickets"],
 *     resourceAllowlist: ["mcp://docs/handbook"],
 *   });
 *   typeof guard;
 *   // → "function"
 */
function serverGuard(opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || McpError;
  var requireBearer = opts.requireBearer !== false;
  var verifyBearer  = opts.verifyBearer || null;
  if (requireBearer && typeof verifyBearer !== "function") {
    throw errorClass.factory("BAD_OPTS",
      "mcp.serverGuard: verifyBearer required when requireBearer=true");
  }
  var redirectUriAllowlist = Array.isArray(opts.redirectUriAllowlist)
    ? opts.redirectUriAllowlist.slice() : [];
  var allowDynamicRegister = opts.allowDynamicRegister === true;
  var registerClientAllowlist = typeof opts.registerClientAllowlist === "function"
    ? opts.registerClientAllowlist : null;
  if (allowDynamicRegister && !registerClientAllowlist) {
    throw errorClass.factory("BAD_OPTS",
      "mcp.serverGuard: allowDynamicRegister=true requires registerClientAllowlist function");
  }
  var toolAllowlist     = Array.isArray(opts.toolAllowlist)     ? opts.toolAllowlist     : null;
  var resourceAllowlist = Array.isArray(opts.resourceAllowlist) ? opts.resourceAllowlist : null;
  nb.requirePositiveFiniteIntIfPresent(opts.maxBodyBytes, "mcp.serverGuard: opts.maxBodyBytes", errorClass, "BAD_MAX_BYTES");
  var maxBodyBytes = opts.maxBodyBytes || C.BYTES.mib(1);
  var auditOn = opts.audit !== false;

  function _emitDenied(req, action, reason, metadata) {
    if (!auditOn) return;
    audit.safeEmit({
      action:   action,
      outcome:  "denied",
      reason:   reason,
      metadata: Object.assign({
        ip: requestHelpers.clientIp(req),
        path: req && req.url,
      }, metadata || {}),
    });
  }

  return function mcpGuard(req, res, next) {
    Promise.resolve().then(function () {
      var token = _readBearer(req);
      if (requireBearer) {
        if (!token) {
          _emitDenied(req, "mcp.auth.missing-bearer", "no bearer", {});
          if (typeof res.setHeader === "function") {
            res.setHeader("WWW-Authenticate",
              "Bearer realm=\"mcp\", error=\"invalid_request\"");
          }
          return refuse(res, JSONRPC_AUTH_REQUIRED, "authentication required");
        }
      }
      var claimsPromise = token && verifyBearer
        ? Promise.resolve(verifyBearer(token, req))
        : Promise.resolve(null);

      return claimsPromise.then(function (claims) {
        if (requireBearer && !claims) {
          _emitDenied(req, "mcp.auth.invalid-bearer", "bearer rejected", {});
          if (typeof res.setHeader === "function") {
            res.setHeader("WWW-Authenticate",
              "Bearer realm=\"mcp\", error=\"invalid_token\"");
          }
          return refuse(res, JSONRPC_AUTH_REQUIRED, "authentication failed");
        }
        req.mcpClaims = claims || null;

        var path = String(req.url || "").split("?")[0];
        if (path === "/register" || path.endsWith("/register")) {
          if (!allowDynamicRegister) {
            _emitDenied(req, "mcp.register.refused-static", "dynamic registration disabled", { path: path });
            return refuse(res, JSONRPC_METHOD_NOT_FOUND, "dynamic client registration is not permitted");
          }
        }

        return _readBodyBuffered(req, maxBodyBytes, errorClass).then(function (rawBody) {
          var parsed;
          try { parsed = parseRequest(rawBody, { errorClass: errorClass }); }
          catch (e) {
            _emitDenied(req, "mcp.envelope.refused", e.message, {});
            return refuse(res, JSONRPC_PARSE_ERROR, e.message);
          }
          var method = parsed.method;
          var params = parsed.params || {};

          if (params && typeof params === "object" && params.redirect_uri !== undefined) {
            try { _checkRedirectUri(params.redirect_uri, redirectUriAllowlist, errorClass); }
            catch (e) {
              _emitDenied(req, "mcp.redirect-uri.refused", e.message,
                { redirectUri: params.redirect_uri });
              return refuse(res, JSONRPC_INVALID_PARAMS, e.message, parsed.id);
            }
          }

          if (method === "tools/call") {
            var toolName = params && typeof params === "object" ? params.name : null;
            if (typeof toolName !== "string" || toolName.length > TOOL_NAME_MAX || !TOOL_NAME_RE.test(toolName)) {
              _emitDenied(req, "mcp.tool.bad-name", "tool name shape", { toolName: toolName });
              return refuse(res, JSONRPC_INVALID_PARAMS, "tool name malformed", parsed.id);
            }
            if (toolAllowlist && toolAllowlist.indexOf(toolName) === -1) {
              _emitDenied(req, "mcp.tool.refused", "not in allowlist", { toolName: toolName });
              return refuse(res, JSONRPC_METHOD_NOT_FOUND, "tool not permitted", parsed.id);
            }
          }
          if (method === "resources/read") {
            var resourceUri = params && typeof params === "object" ? params.uri : null;
            if (typeof resourceUri !== "string" || resourceUri.length > RESOURCE_NAME_MAX || !RESOURCE_NAME_RE.test(resourceUri)) {
              _emitDenied(req, "mcp.resource.bad-uri", "resource uri shape", { resourceUri: resourceUri });
              return refuse(res, JSONRPC_INVALID_PARAMS, "resource uri malformed", parsed.id);
            }
            if (resourceAllowlist && resourceAllowlist.indexOf(resourceUri) === -1) {
              _emitDenied(req, "mcp.resource.refused", "not in allowlist", { resourceUri: resourceUri });
              return refuse(res, JSONRPC_METHOD_NOT_FOUND, "resource not permitted", parsed.id);
            }
          }

          req.mcpRequest = parsed;
          if (auditOn) {
            audit.safeEmit({
              action:   "mcp.request",
              outcome:  "success",
              metadata: { method: method, hasClaims: !!claims },
            });
          }
          if (typeof next === "function") next();
          else if (!res.writableEnded) refuse(res, JSONRPC_METHOD_NOT_FOUND, "handler not wired");
        });
      });
    }).catch(function (err) {
      _emitDenied(req, "mcp.guard.error", err.message || "guard error", {});
      if (!res.writableEnded) refuse(res, JSONRPC_INTERNAL_ERROR, "internal guard error");
    });
  };
}

module.exports = {
  serverGuard:    serverGuard,
  parseRequest:   parseRequest,
  refuse:         refuse,
};
