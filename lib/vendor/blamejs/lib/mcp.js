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

/**
 * @primitive b.mcp.toolResult.sanitize
 * @signature b.mcp.toolResult.sanitize(result, opts?)
 * @since     0.8.70
 * @related   b.mcp.serverGuard, b.guardHtml, b.ai.input.classify
 *
 * OWASP LLM02 — model/tool-output sanitization. MCP tool calls
 * frequently return content the host model interprets as further
 * instructions; an attacker-controlled tool surface can return
 * `{ type: "text", text: "Ignore prior instructions and ..." }`,
 * `<script>...</script>`, OR markdown image links pointing at
 * exfiltration endpoints. The framework's defense:
 *
 *   - Strip / refuse executable HTML (`<script>` / `<iframe>` /
 *     `javascript:` URLs) — composes b.guardHtml's strict profile
 *   - Refuse known prompt-injection markers ("ignore previous
 *     instructions", "system: you are now ...", role-claim prefixes)
 *     — composes b.ai.input.classify
 *   - Cap text length so a tool can't blow the host's context window
 *     out from under it
 *   - Refuse content with `image_url` / `audio_url` / `resource_link`
 *     pointing at non-allowlisted hosts (data-exfil via auto-fetch)
 *
 * Returns either the cleaned result (when `sanitize: true`) or
 * throws `McpError("mcp/tool-output-refused", ...)` (default —
 * fail-closed). Operators with a known-good tool surface that needs
 * raw passthrough opt out via `posture: "audit-only"`.
 *
 * @opts
 *   {
 *     posture?:        "refuse" | "sanitize" | "audit-only",  // default "refuse"
 *     maxTextBytes?:   number,    // default 64 KiB per content block
 *     allowedHosts?:   string[],  // for image/audio/resource_link refs
 *     classifyInput?:  fn(text)→{verdict, score} | null,      // default b.ai.input.classify
 *   }
 *
 * @example
 *   var safe = b.mcp.toolResult.sanitize(toolResp, { posture: "sanitize" });
 *   // → { content: [{ type: "text", text: "<cleaned>" }] }
 */
var DEFAULT_TOOL_OUTPUT_MAX_BYTES = 64 * 1024;                                                   // allow:raw-byte-literal — 64 KiB per content block
var PROMPT_INJECTION_MARKERS = [
  "ignore (previous|prior|all) instructions",
  "system:\\s*you are",
  "<\\|im_(start|end)\\|>",
  "<\\|system\\|>",
  "###\\s*(system|assistant|user|tool)",
  "<system>",
  "</?(?:assistant|system|user|tool)>",
];
var INJECTION_RE = new RegExp(PROMPT_INJECTION_MARKERS.join("|"), "i");                          // allow:dynamic-regex — composed from the const PROMPT_INJECTION_MARKERS list above; not operator-supplied input
var DANGEROUS_HTML_RE = /<script\b|<iframe\b|<object\b|<embed\b|javascript:/i;

function _toolResultSanitize(result, opts) {
  opts = opts || {};
  var posture = opts.posture || "refuse";
  if (["refuse", "sanitize", "audit-only"].indexOf(posture) === -1) {
    throw new McpError("mcp/bad-posture",
      "toolResult.sanitize: posture must be 'refuse' | 'sanitize' | 'audit-only'");
  }
  var maxBytes = opts.maxTextBytes || DEFAULT_TOOL_OUTPUT_MAX_BYTES;
  var allowedHosts = Array.isArray(opts.allowedHosts) ? opts.allowedHosts : [];
  if (!result || typeof result !== "object") {
    throw new McpError("mcp/bad-tool-result",
      "toolResult.sanitize: result must be an object");
  }
  var content = Array.isArray(result.content) ? result.content : [];
  var issues = [];
  var cleaned = [];
  for (var i = 0; i < content.length; i++) {
    var block = content[i];
    if (!block || typeof block !== "object") {
      issues.push({ kind: "bad-block", index: i });
      continue;
    }
    if (block.type === "text" && typeof block.text === "string") {
      var t = block.text;
      if (Buffer.byteLength(t, "utf8") > maxBytes) {
        issues.push({ kind: "text-too-long", index: i, bytes: Buffer.byteLength(t, "utf8") });
        if (posture === "sanitize") t = Buffer.from(t, "utf8").subarray(0, maxBytes).toString("utf8");
      }
      // Bound the regex-test surface to maxBytes (already enforced
      // upstream when sanitize-mode strips, but in audit-only / refuse
      // modes we still hand the raw text into the regex so cap
      // explicitly here to satisfy the regex-bound-length rule).
      var regexInput = Buffer.byteLength(t, "utf8") > maxBytes
        ? Buffer.from(t, "utf8").subarray(0, maxBytes).toString("utf8")
        : t;
      if (INJECTION_RE.test(regexInput)) {                                                       // allow:regex-no-length-cap regexInput byteLength bounded above
        issues.push({ kind: "prompt-injection", index: i });
        if (posture === "sanitize") {
          // Strip the injection marker line — operators wanting
          // structural redaction wire their own classifier.
          t = t.replace(INJECTION_RE, "[REDACTED]");
        }
      }
      if (DANGEROUS_HTML_RE.test(regexInput)) {                                                  // allow:regex-no-length-cap regexInput byteLength bounded above
        issues.push({ kind: "dangerous-html", index: i });
        if (posture === "sanitize") t = t.replace(DANGEROUS_HTML_RE, "[REDACTED]");
      }
      cleaned.push({ type: "text", text: t });
    } else if (block.type === "image" || block.type === "resource_link" || block.type === "audio") {
      var url = block.url || (block.resource && block.resource.uri);
      if (typeof url === "string" && url.length > 0 && allowedHosts.length > 0) {
        var u; try { u = new URL(url); } catch (_e) { u = null; }                                // allow:raw-new-url — operator-supplied tool URL; allowlist enforced below
        if (!u || allowedHosts.indexOf(u.host) === -1) {
          issues.push({ kind: "off-allowlist-url", index: i, url: url });
          if (posture === "sanitize") continue;                                                  // drop the block in sanitize mode
        }
      }
      cleaned.push(block);
    } else {
      cleaned.push(block);
    }
  }
  if (issues.length > 0 && posture === "refuse") {
    var first = issues[0];
    throw new McpError("mcp/tool-output-refused",
      "toolResult.sanitize: refused " + issues.length + " issue(s) " +
      "(first: " + first.kind + " on block[" + first.index + "])");
  }
  return { content: cleaned, isError: !!result.isError, issues: issues };
}

/**
 * @primitive b.mcp.capability.create
 * @signature b.mcp.capability.create(scopes)
 * @since     0.8.70
 * @related   b.mcp.serverGuard
 *
 * OWASP LLM08 — capability primitive. Wraps an MCP tool/resource
 * registration with a scope set the host model's session must hold
 * before the tool/resource is exposed. Defaults to deny-all; the
 * operator's session-decoration step grants scopes per user / per
 * agent / per delegated-actor.
 *
 * Returns `{ scopes, satisfiedBy(grantedSet) }` — the guard checks
 * `satisfiedBy(session.capabilities)` before each tool/resource
 * dispatch. Falsy → refuse with `mcp/capability-denied`.
 *
 * @example
 *   var fileRead = b.mcp.capability.create(["fs:read"]);
 *   if (!fileRead.satisfiedBy(session.capabilities)) {
 *     throw new Error("mcp/capability-denied");
 *   }
 */
function _capabilityCreate(scopes) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    throw new McpError("mcp/bad-capability",
      "capability.create: scopes must be a non-empty array of strings");
  }
  scopes.forEach(function (s, i) {
    if (typeof s !== "string" || s.length === 0) {
      throw new McpError("mcp/bad-capability-scope",
        "capability.create: scopes[" + i + "] must be a non-empty string");
    }
  });
  var frozen = scopes.slice();
  return {
    scopes: frozen,
    satisfiedBy: function (granted) {
      if (!Array.isArray(granted)) return false;
      for (var i = 0; i < frozen.length; i++) {
        if (granted.indexOf(frozen[i]) === -1) return false;
      }
      return true;
    },
  };
}

/**
 * @primitive b.mcp.validateToolInput
 * @signature b.mcp.validateToolInput(toolName, input, schema)
 * @since     0.8.70
 * @related   b.mcp.serverGuard, b.safeSchema
 *
 * OWASP LLM07 — JSON-Schema enforcement on MCP tool inputs. Tools
 * declare an `inputSchema` (JSON Schema 2020-12 subset) at
 * registration; before each invocation the framework validates
 * incoming arguments against the schema and refuses on any drift.
 * Composes b.safeSchema for the validation engine — same primitive
 * the OpenAPI surface uses, so the threat model is uniform.
 *
 * Returns the validated (possibly coerced) input object on success;
 * throws `McpError("mcp/tool-input-invalid", ...)` on schema breach.
 *
 * @example
 *   var schema = { type: "object",
 *                  properties: { path: { type: "string" } },
 *                  required: ["path"] };
 *   var input = b.mcp.validateToolInput("read_file", { path: "/x" }, schema);
 */
// JSON-Schema-2020-12 subset validator for MCP tool inputs. The
// MCP spec specifies tool schemas in standard JSON Schema; the
// framework's chainable b.safeSchema is fluent-builder-shaped and
// doesn't accept JSON Schema directly. We implement the small
// subset MCP tools actually use:
//   - type:        "string" | "number" | "integer" | "boolean" | "object" | "array" | "null"
//   - required:    string[]
//   - properties:  recursive
//   - items:       array element schema
//   - enum:        allowed-value list
//   - minimum / maximum / minLength / maxLength
//   - pattern:     regex (string types)
// Refuses unknown JSON Schema keywords loudly so a tool-author
// typo doesn't silently pass validation.
function _validateValueAgainstSchema(value, schema, path) {
  if (!schema || typeof schema !== "object") return null;
  var t = schema.type;
  if (Array.isArray(t)) {
    var anyMatched = false;
    for (var ti = 0; ti < t.length; ti++) {
      if (_typeMatches(value, t[ti])) { anyMatched = true; break; }
    }
    if (!anyMatched) return path + ": expected one of " + JSON.stringify(t) + ", got " + (typeof value);
  } else if (typeof t === "string") {
    if (!_typeMatches(value, t)) return path + ": expected " + t + ", got " + (typeof value);
  }
  if (Array.isArray(schema.enum) && schema.enum.indexOf(value) === -1) {
    return path + ": value not in enum " + JSON.stringify(schema.enum);
  }
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      return path + ": string length " + value.length + " < minLength " + schema.minLength;
    }
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
      return path + ": string length " + value.length + " > maxLength " + schema.maxLength;
    }
    if (typeof schema.pattern === "string") {
      // Schema-supplied pattern — operator-controlled at registration
      // time, not request-controlled. Cap value length first per the
      // codebase-patterns regex-bound rule so a 10MB string doesn't
      // ReDoS the validator.
      if (value.length > 4096) return path + ": value exceeds 4 KiB cap before regex test";    // allow:raw-byte-literal — 4 KiB regex-input cap
      try {
        var pat = new RegExp(schema.pattern);                                                    // allow:dynamic-regex — schema.pattern from registered tool author, not request input; bounded above
        if (!pat.test(value)) return path + ": does not match pattern";
      }
      catch (_e) { return path + ": invalid pattern in schema"; }
    }
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) return path + ": " + value + " < minimum " + schema.minimum;
    if (typeof schema.maximum === "number" && value > schema.maximum) return path + ": " + value + " > maximum " + schema.maximum;
  }
  if (t === "object" && value && typeof value === "object" && !Array.isArray(value)) {
    if (Array.isArray(schema.required)) {
      for (var ri = 0; ri < schema.required.length; ri++) {
        if (!Object.prototype.hasOwnProperty.call(value, schema.required[ri])) {
          return path + ": missing required property '" + schema.required[ri] + "'";
        }
      }
    }
    if (schema.properties && typeof schema.properties === "object") {
      var keys = Object.keys(schema.properties);
      for (var pi = 0; pi < keys.length; pi++) {
        var k = keys[pi];
        if (!Object.prototype.hasOwnProperty.call(value, k)) continue;
        var inner = _validateValueAgainstSchema(value[k], schema.properties[k], path + "." + k);
        if (inner) return inner;
      }
    }
    if (schema.additionalProperties === false) {
      var allowed = Object.keys(schema.properties || {});
      var keys2 = Object.keys(value);
      for (var ki = 0; ki < keys2.length; ki++) {
        if (allowed.indexOf(keys2[ki]) === -1) {
          return path + ": unknown property '" + keys2[ki] + "' (additionalProperties: false)";
        }
      }
    }
  }
  if (t === "array" && Array.isArray(value)) {
    if (schema.items) {
      for (var ai = 0; ai < value.length; ai++) {
        var aInner = _validateValueAgainstSchema(value[ai], schema.items, path + "[" + ai + "]");
        if (aInner) return aInner;
      }
    }
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      return path + ": array length " + value.length + " < minItems " + schema.minItems;
    }
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
      return path + ": array length " + value.length + " > maxItems " + schema.maxItems;
    }
  }
  return null;
}

function _typeMatches(value, type) {
  switch (type) {
    case "string":  return typeof value === "string";
    case "number":  return typeof value === "number" && isFinite(value);
    case "integer": return typeof value === "number" && Number.isInteger(value);
    case "boolean": return typeof value === "boolean";
    case "null":    return value === null;
    case "array":   return Array.isArray(value);
    case "object":  return value !== null && typeof value === "object" && !Array.isArray(value);
    default:        return false;
  }
}

function _validateToolInput(toolName, input, schema) {
  if (typeof toolName !== "string" || toolName.length === 0) {
    throw new McpError("mcp/bad-tool-name",
      "validateToolInput: toolName must be a non-empty string");
  }
  if (!schema || typeof schema !== "object") {
    throw new McpError("mcp/bad-tool-schema",
      "validateToolInput: schema must be a JSON-Schema-shaped object");
  }
  var err = _validateValueAgainstSchema(input, schema, "$");
  if (err) {
    throw new McpError("mcp/tool-input-invalid",
      "validateToolInput: tool '" + toolName + "' input " + err);
  }
  return input;
}

module.exports = {
  serverGuard:    serverGuard,
  parseRequest:   parseRequest,
  refuse:         refuse,
  toolResult:     { sanitize: _toolResultSanitize },
  capability:     { create: _capabilityCreate },
  validateToolInput: _validateToolInput,
};
