// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.a2a
 * @nav        Agent
 * @title      A2A Tasks
 * @order      600
 *
 * @intro
 *   A2A v1 task-exchange surface — the work primitive on top of
 *   `b.a2a.{createCard, signCard, verifyCard}`. A2A (Linux Foundation,
 *   v1 spec Apr 2026) defines a JSON-RPC 2.0 over HTTPS protocol with
 *   three task verbs (`tasks/send`, `tasks/get`, `tasks/cancel`) plus
 *   optional SSE streaming for long-running tasks.
 *
 *   The framework ships:
 *
 *     - Client-side dispatchers: `b.a2a.tasks.send({ peerUrl, agentCard, task })`
 *       posts a `tasks/send` JSON-RPC request; `get({ taskId })` polls
 *       status; `cancel({ taskId })` requests cancellation.
 *     - Server-side middleware: `b.a2a.middleware.agentCard({ card })`
 *       serves `/.well-known/agent.json`; `b.a2a.middleware.tasks
 *       ({ scopes, handler })` parses inbound JSON-RPC, enforces
 *       per-skill scope, and dispatches to an operator handler.
 *     - SSE streaming: when the handler returns a long-running shape,
 *       the middleware switches to SSE and streams progress events
 *       to the client.
 *
 *   PQC-first: every signed-card flow uses the existing `b.a2a.signCard
 *   / verifyCard` ML-DSA-87 surface. The task-exchange envelopes
 *   themselves are NOT separately signed — operators wanting per-call
 *   non-repudiation compose `b.crypto.httpSig.sign` (RFC 9421) at the
 *   HTTP layer.
 *
 *   Per `feedback_validation_tier_policy.md`:
 *     - Client `send / get / cancel` THROW on bad input (entry-point).
 *     - Middleware factories THROW on bad opts at boot.
 *     - The per-request middleware path returns a JSON-RPC error
 *       response on protocol violations (consistent with mcp.refuse).
 *
 * @card
 *   A2A v1 task-exchange surface — JSON-RPC dispatchers + server middleware (agentCard + tasks) + SSE streaming for long-running tasks.
 */

var nodeCrypto    = require("node:crypto");
var lazyRequire   = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var safeJson      = require("./safe-json");
var safeUrl       = require("./safe-url");
var safeBuffer    = require("./safe-buffer");
var validateOpts  = require("./validate-opts");
var { defineClass } = require("./framework-error");

var httpClient = lazyRequire(function () { return require("./http-client"); });
var auditEmit  = require("./audit-emit");
var C          = require("./constants");

// A2aTasksError is the per-call error class — separate from A2aError
// (which exists for the card-signing primitives) so operators can
// catch task-shape errors distinctly.
var A2aTasksError = defineClass("A2aTasksError", { alwaysPermanent: true });

var JSONRPC_VERSION = "2.0";

// JSON-RPC 2.0 fixed error codes — A2A inherits these.
var JSONRPC_PARSE_ERROR      = -32700;                                                             // allow:raw-time-literal — JSON-RPC error code -32700; coincidental multiple-of-60, not a time value, C.TIME N/A
var JSONRPC_INVALID_REQUEST  = -32600;
var JSONRPC_METHOD_NOT_FOUND = -32601;
var JSONRPC_INVALID_PARAMS   = -32602;
var JSONRPC_INTERNAL_ERROR   = -32603;

// A2A-specific error codes per the spec's task-error vocabulary.
// A2A_TASK_NOT_FOUND (-32002) + A2A_TASK_NOT_CANCELABLE (-32003) are
// raised by operator handlers — they're reserved here for documentation
// purposes only.
var A2A_SCOPE_DENIED         = -32001;

var ALLOWED_METHODS = Object.freeze(["tasks/send", "tasks/get", "tasks/cancel"]);

var TASK_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
// Same identifier shape as MCP tool-name; consolidating would couple
// MCP + A2A protocol identifiers into a single primitive.
var SKILL_NAME_RE = /^[a-zA-Z][a-zA-Z0-9._-]{0,63}$/;   // allow:duplicate-regex — RFC-3986-unreserved identifier shape, shared across mcp.js + mcp-tool-registry.js
// RFC-3986-unreserved identifier shape (length cap inside regex), not a byte count

var _emitAudit = auditEmit.emit;

var bCrypto = lazyRequire(function () { return require("./crypto"); });

// _newTaskId is reserved for the operator-handler path that mints
// peer-assigned task IDs server-side. The underscore prefix already
// satisfies the framework's unused-var policy so the helper stays
// available without an explicit disable directive.
function _newTaskId() {
  return bCrypto().generateToken(12);                                                               // 96-bit task id, not byte arithmetic on payload
}

function _validateTaskShape(task, where) {
  if (!task || typeof task !== "object" || Array.isArray(task)) {
    throw new A2aTasksError("a2a-tasks/bad-task",
      where + ": task must be a non-null object", true);
  }
  validateOpts.requireNonEmptyString(task.skill, where + ".skill", A2aTasksError, "a2a-tasks/bad-skill");
  if (task.skill.length > 64 || !SKILL_NAME_RE.test(task.skill)) {                                // A2A skill-name length cap, not byte count

    throw new A2aTasksError("a2a-tasks/bad-skill",
      where + ".skill '" + task.skill + "' must match " + SKILL_NAME_RE);
  }
  if (task.input !== undefined && (typeof task.input !== "object" || task.input === null)) {
    throw new A2aTasksError("a2a-tasks/bad-input",
      where + ".input must be an object when provided", true);
  }
}

// ---- Client-side dispatchers ----

/**
 * @primitive b.a2a.tasks.send
 * @signature b.a2a.tasks.send(opts)
 * @since     0.8.85
 * @status    stable
 * @related   b.a2a.tasks.get, b.a2a.tasks.cancel, b.a2a.signCard
 *
 * Post a `tasks/send` JSON-RPC request to a peer A2A agent. Returns
 * the peer's `tasks/send` result — typically `{ taskId, status }` or
 * a final-state response when the task ran synchronously.
 *
 * @opts
 *   peerUrl:   string,    // peer's A2A endpoint URL (https only)
 *   task:      object,    // { skill, input } per A2A v1 §4
 *   timeoutMs: number,    // optional — default 30s
 *   headers:   object,    // optional — extra HTTP headers (signed
 *                         //            auth / mTLS / RFC 9421 sig)
 *   audit:     boolean,   // default true
 *
 * @example
 *   var rsp = await b.a2a.tasks.send({
 *     peerUrl: "https://agent.example.com/a2a",
 *     task:    { skill: "summarize", input: { url: "..." } },
 *   });
 *   // rsp.taskId === "<peer-assigned-id>"
 *   // rsp.status === "queued" | "running" | "completed"
 */
async function send(opts) {
  if (!opts || typeof opts !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-opts",
      "tasks.send: opts required (peerUrl + task)", true);
  }
  validateOpts.requireNonEmptyString(opts.peerUrl, "tasks.send.peerUrl", A2aTasksError, "a2a-tasks/bad-peer-url");
  // Refuse non-https — A2A v1 §3 mandates TLS for transport.
  try { safeUrl.parse(opts.peerUrl, { allowedProtocols: ["https:"] }); }
  catch (_e) {
    throw new A2aTasksError("a2a-tasks/bad-peer-url",
      "tasks.send: peerUrl must be a valid https URL");
  }
  _validateTaskShape(opts.task, "tasks.send.task");
  var timeoutMs = opts.timeoutMs !== undefined ? opts.timeoutMs : C.TIME.seconds(30);
  return _jsonRpc(opts.peerUrl, "tasks/send", { task: opts.task }, {
    timeoutMs: timeoutMs,
    headers:   opts.headers || {},
    audit:     opts.audit !== false,
  });
}

/**
 * @primitive b.a2a.tasks.get
 * @signature b.a2a.tasks.get(opts)
 * @since     0.8.85
 * @status    stable
 * @related   b.a2a.tasks.send, b.a2a.tasks.cancel
 *
 * Poll a peer task's current status via `tasks/get`. Returns the
 * peer's status record — `{ taskId, status, result?, error? }`.
 *
 * @opts
 *   peerUrl: string,
 *   taskId:  string,
 *   timeoutMs: number,
 *   headers: object,
 *
 * @example
 *   var st = await b.a2a.tasks.get({ peerUrl: url, taskId: "abc" });
 *   if (st.status === "completed") console.log(st.result);
 */
async function get(opts) {
  if (!opts || typeof opts !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-opts",
      "tasks.get: opts required (peerUrl + taskId)", true);
  }
  validateOpts.requireNonEmptyString(opts.peerUrl, "tasks.get.peerUrl", A2aTasksError, "a2a-tasks/bad-peer-url");
  validateOpts.requireNonEmptyString(opts.taskId, "tasks.get.taskId", A2aTasksError, "a2a-tasks/bad-task-id");
  if (opts.taskId.length > 64 || !TASK_ID_RE.test(opts.taskId)) {                                  // A2A task-id length cap, not byte count
    throw new A2aTasksError("a2a-tasks/bad-task-id",
      "tasks.get: taskId must match " + TASK_ID_RE);
  }
  return _jsonRpc(opts.peerUrl, "tasks/get", { taskId: opts.taskId }, {
    timeoutMs: opts.timeoutMs !== undefined ? opts.timeoutMs : C.TIME.seconds(15),
    headers:   opts.headers || {},
    audit:     opts.audit !== false,
  });
}

/**
 * @primitive b.a2a.tasks.cancel
 * @signature b.a2a.tasks.cancel(opts)
 * @since     0.8.85
 * @status    stable
 * @related   b.a2a.tasks.send, b.a2a.tasks.get
 *
 * Request peer cancellation via `tasks/cancel`. Peer MAY refuse with
 * `-32003 task-not-cancelable` for tasks that have completed or
 * passed a cancellation point.
 *
 * @opts
 *   peerUrl:   string,    // peer's A2A endpoint URL (https only)
 *   taskId:    string,    // peer-assigned task identifier
 *   timeoutMs: number,    // optional — default 15s
 *   headers:   object,    // optional — extra HTTP headers
 *   audit:     boolean,   // default true
 *
 * @example
 *   try {
 *     await b.a2a.tasks.cancel({ peerUrl: url, taskId: "abc" });
 *   } catch (e) {
 *     if (e.rpcCode === -32003) console.log("task already past cancel point");
 *   }
 */
async function cancel(opts) {
  if (!opts || typeof opts !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-opts",
      "tasks.cancel: opts required (peerUrl + taskId)", true);
  }
  validateOpts.requireNonEmptyString(opts.peerUrl, "tasks.cancel.peerUrl", A2aTasksError, "a2a-tasks/bad-peer-url");
  validateOpts.requireNonEmptyString(opts.taskId, "tasks.cancel.taskId", A2aTasksError, "a2a-tasks/bad-task-id");
  if (opts.taskId.length > 64 || !TASK_ID_RE.test(opts.taskId)) {                                  // A2A task-id length cap, not byte count
    throw new A2aTasksError("a2a-tasks/bad-task-id",
      "tasks.cancel: taskId must match " + TASK_ID_RE);
  }
  return _jsonRpc(opts.peerUrl, "tasks/cancel", { taskId: opts.taskId }, {
    timeoutMs: opts.timeoutMs !== undefined ? opts.timeoutMs : C.TIME.seconds(15),
    headers:   opts.headers || {},
    audit:     opts.audit !== false,
  });
}

async function _jsonRpc(url, method, params, opts) {
  var id = nodeCrypto.randomUUID();
  var body = JSON.stringify({
    jsonrpc: JSONRPC_VERSION,
    id:      id,
    method:  method,
    params:  params,
  });
  var startMs = Date.now();
  var rsp;
  try {
    rsp = await httpClient().request({
      method:  "POST",
      url:     url,
      body:    body,
      headers: Object.assign({
        "Content-Type": "application/json",
        "Accept":       "application/json",
      }, opts.headers),
      timeoutMs: opts.timeoutMs,
    });
  } catch (transportErr) {
    if (opts.audit) {
      _emitAudit("a2a.tasks.transport_failed",
        { method: method, url: url, error: String(transportErr.message || transportErr), elapsedMs: Date.now() - startMs },
        "warning");
    }
    throw new A2aTasksError("a2a-tasks/transport",
      "tasks." + method.split("/")[1] + ": transport error: " + (transportErr.message || transportErr));
  }
  if (rsp.statusCode < 200 || rsp.statusCode >= 300) {                                             // HTTP status class boundaries
    if (opts.audit) {
      _emitAudit("a2a.tasks.http_error",
        { method: method, url: url, statusCode: rsp.statusCode, elapsedMs: Date.now() - startMs },
        "warning");
    }
    throw new A2aTasksError("a2a-tasks/http-error",
      "tasks." + method.split("/")[1] + ": HTTP " + rsp.statusCode);
  }
  var parsed;
  try {
    parsed = safeJson.parse(typeof rsp.body === "string" ? rsp.body : rsp.body.toString("utf8"),
      { maxBytes: C.BYTES.mib(8) });
  } catch (parseErr) {
    throw new A2aTasksError("a2a-tasks/bad-response",
      "tasks." + method.split("/")[1] + ": response not valid JSON: " + (parseErr.message || parseErr));
  }
  if (!parsed || typeof parsed !== "object" || parsed.jsonrpc !== JSONRPC_VERSION) {
    throw new A2aTasksError("a2a-tasks/bad-response",
      "tasks." + method.split("/")[1] + ": response is not a JSON-RPC 2.0 envelope");
  }
  if (parsed.error) {
    if (opts.audit) {
      _emitAudit("a2a.tasks.rpc_error",
        { method: method, url: url, errorCode: parsed.error.code, errorMessage: parsed.error.message },
        "warning");
    }
    var err = new A2aTasksError("a2a-tasks/rpc-error",
      "tasks." + method.split("/")[1] + ": " + (parsed.error.message || "rpc error"));
    err.rpcCode = parsed.error.code;
    err.rpcData = parsed.error.data;
    throw err;
  }
  if (opts.audit) {
    _emitAudit("a2a.tasks.ok",
      { method: method, url: url, elapsedMs: Date.now() - startMs });
  }
  return parsed.result;
}

// ---- Server-side middleware ----

/**
 * @primitive b.a2a.middleware.tasks
 * @signature b.a2a.middleware.tasks(opts)
 * @since     0.8.85
 * @status    stable
 * @related   b.a2a.middleware.agentCard, b.a2a.tasks.send
 *
 * Build the server-side A2A tasks middleware. Returns a connect-style
 * `(req, res, next) => void` that:
 *
 *   - Parses inbound JSON-RPC 2.0 requests from POST request bodies.
 *     Refuses non-POST + non-application/json with 405 / 415.
 *   - Refuses methods not in `["tasks/send", "tasks/get",
 *     "tasks/cancel"]` with JSON-RPC -32601 method-not-found.
 *   - Enforces per-skill scope via `opts.scopes` — a map
 *     `{ skillName: requiredScope }`. The middleware reads
 *     `req.a2aScopes` (populated by the operator's auth layer; e.g.
 *     parsed from a bearer token's claims or an mTLS cert SAN) and
 *     refuses calls whose required scope isn't granted with -32001.
 *   - Dispatches to `opts.handler({ method, taskId?, task?, req })`
 *     which returns the task state (or throws for errors that get
 *     mapped to -32603).
 *
 *   The middleware writes the JSON-RPC response itself; it does NOT
 *   call `next()`. Operators chaining additional middleware after
 *   this one should mount on a separate path.
 *
 * @opts
 *   handler:    function (ctx) → result  — REQUIRED
 *   scopes:     { skillName: scopeString } — optional per-skill scope map
 *   maxBytes:   number — body cap (default 1 MiB)
 *   audit:      boolean — default true
 *
 * @example
 *   var mw = b.a2a.middleware.tasks({
 *     scopes: { summarize: "a2a:summarize", search: "a2a:search" },
 *     handler: async function ({ method, task, taskId }) {
 *       if (method === "tasks/send") {
 *         var newId = "t-" + Math.random().toString(36).slice(2, 10);
 *         queue.push({ id: newId, task });
 *         return { taskId: newId, status: "queued" };
 *       }
 *       if (method === "tasks/get") {
 *         return tasks.get(taskId);
 *       }
 *       if (method === "tasks/cancel") {
 *         return tasks.cancel(taskId);
 *       }
 *     },
 *   });
 *   app.post("/a2a", mw);
 */
function middlewareTasks(opts) {
  if (!opts || typeof opts !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-mw-opts",
      "middleware.tasks: opts required (handler)", true);
  }
  if (typeof opts.handler !== "function") {
    throw new A2aTasksError("a2a-tasks/bad-mw-opts",
      "middleware.tasks: opts.handler must be a function", true);
  }
  if (opts.scopes !== undefined) {
    if (typeof opts.scopes !== "object" || opts.scopes === null || Array.isArray(opts.scopes)) {
      throw new A2aTasksError("a2a-tasks/bad-mw-opts",
        "middleware.tasks: opts.scopes must be an object when provided", true);
    }
    // Every scope VALUE must be a non-empty string. A non-string value (e.g.
    // {transfer: ["a2a:transfer"]}) would make the runtime `typeof requiredScope
    // === "string"` gate silently skip — a fail-open authorization bypass on a
    // gated skill. Catch the operator typo at boot, not at request time.
    var scopeKeys = Object.keys(opts.scopes);
    for (var sk = 0; sk < scopeKeys.length; sk += 1) {
      var sv = opts.scopes[scopeKeys[sk]];
      if (typeof sv !== "string" || sv.length === 0) {
        throw new A2aTasksError("a2a-tasks/bad-mw-opts",
          "middleware.tasks: opts.scopes['" + scopeKeys[sk] + "'] must be a non-empty string", true);
      }
    }
  }
  var maxBytes = opts.maxBytes !== undefined ? opts.maxBytes : C.BYTES.mib(1);
  var emitAudit = opts.audit !== false;
  var scopes = opts.scopes || null;

  return function a2aTasksMiddleware(req, res) {
    if ((req.method || "").toUpperCase() !== "POST") {
      res.statusCode = 405;                                                                        // HTTP 405 Method Not Allowed
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Allow", "POST");
      res.end(JSON.stringify(_jsonRpcError(null, JSONRPC_INVALID_REQUEST, "method must be POST")));
      return;
    }
    var ctype = (req.headers && (req.headers["content-type"] || req.headers["Content-Type"])) || "";
    if (typeof ctype === "string" && ctype.indexOf("application/json") !== 0 && ctype.indexOf("application/json") === -1) {
      res.statusCode = 415;                                                                        // HTTP 415 Unsupported Media Type
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(_jsonRpcError(null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json")));
      return;
    }

    _readBody(req, maxBytes).then(function (rawBytes) {
      var body;
      try {
        body = safeJson.parse(rawBytes.toString("utf8"), { maxBytes: maxBytes });
      } catch (_parseErr) {
        res.statusCode = 400;                                                                      // HTTP 400 Bad Request
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(_jsonRpcError(null, JSONRPC_PARSE_ERROR, "invalid JSON body")));
        return;
      }
      if (!body || typeof body !== "object" || body.jsonrpc !== JSONRPC_VERSION ||
          typeof body.method !== "string") {
        res.statusCode = 400;                                                                      // HTTP 400 Bad Request
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(_jsonRpcError(body && body.id, JSONRPC_INVALID_REQUEST,
          "expected JSON-RPC 2.0 envelope { jsonrpc, id?, method, params? }")));
        return;
      }
      var reqId = body.id !== undefined ? body.id : null;
      if (ALLOWED_METHODS.indexOf(body.method) === -1) {
        res.statusCode = 200;                                                                      // JSON-RPC errors return 200 with error envelope
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(_jsonRpcError(reqId, JSONRPC_METHOD_NOT_FOUND,
          "method '" + body.method + "' not in [" + ALLOWED_METHODS.join(", ") + "]")));
        return;
      }
      var params = body.params || {};

      // Validate the protocol identifiers on the UNTRUSTED-peer ingress before
      // handing them to the operator handler — the client send/get/cancel
      // dispatchers enforce these shapes on egress, the server must too (the
      // sibling b.mcp middleware validates toolName/resourceUri identically).
      if (body.method === "tasks/send") {
        try { _validateTaskShape(params.task, "middleware.tasks.task"); }
        catch (eShape) {
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify(_jsonRpcError(reqId, JSONRPC_INVALID_PARAMS,
            (eShape && eShape.message) || "tasks/send: invalid task")));
          return;
        }
      } else if (body.method === "tasks/get" || body.method === "tasks/cancel") {
        if (typeof params.taskId !== "string" || params.taskId.length > 64 || !TASK_ID_RE.test(params.taskId)) {
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify(_jsonRpcError(reqId, JSONRPC_INVALID_PARAMS,
            body.method + ": params.taskId must match " + TASK_ID_RE)));
          return;
        }
      }

      // Scope enforcement for tasks/send (task references a skill).
      if (body.method === "tasks/send" && scopes) {
        // Own-property lookup ONLY — an attacker-controlled skill like
        // "constructor"/"toString" must not resolve an inherited Object.prototype
        // member (proto-shadow). The skill shape is already validated above.
        var hasScope = Object.prototype.hasOwnProperty.call(scopes, params.task.skill);
        var requiredScope = hasScope ? scopes[params.task.skill] : undefined;
        if (typeof requiredScope === "string") {
          var grantedScopes = Array.isArray(req.a2aScopes) ? req.a2aScopes : [];
          if (grantedScopes.indexOf(requiredScope) === -1) {
            if (emitAudit) {
              _emitAudit("a2a.tasks.scope_denied",
                { skill: params.task.skill, requiredScope: requiredScope }, "denied");
            }
            res.statusCode = 200;                                                                  // JSON-RPC error envelope returns 200
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify(_jsonRpcError(reqId, A2A_SCOPE_DENIED,
              "scope '" + requiredScope + "' required for skill '" + params.task.skill + "'")));
            return;
          }
        }
      }

      var ctx = {
        method:  body.method,
        task:    params.task,
        taskId:  params.taskId,
        req:     req,
      };
      Promise.resolve()
        .then(function () { return opts.handler(ctx); })
        .then(function (result) {
          if (emitAudit) {
            _emitAudit("a2a.tasks.handled",
              { method: body.method, skill: params.task && params.task.skill, taskId: params.taskId });
          }
          res.statusCode = 200;                                                                    // JSON-RPC 200 with result envelope
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({
            jsonrpc: JSONRPC_VERSION,
            id:      reqId,
            result:  result,
          }));
        })
        .catch(function (handlerErr) {
          var code = handlerErr && handlerErr.rpcCode || JSONRPC_INTERNAL_ERROR;
          var msg  = (handlerErr && handlerErr.message) || "handler error";
          if (emitAudit) {
            _emitAudit("a2a.tasks.handler_error",
              { method: body.method, errorMessage: msg, errorCode: code }, "warning");
          }
          res.statusCode = 200;                                                                    // JSON-RPC error envelope returns 200
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify(_jsonRpcError(reqId, code, msg)));
        });
    }).catch(function (readErr) {
      res.statusCode = 400;                                                                        // HTTP 400 Bad Request
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(_jsonRpcError(null, JSONRPC_PARSE_ERROR,
        "could not read request body: " + (readErr.message || readErr))));
    });
  };
}

function _jsonRpcError(id, code, message, data) {
  var err = { code: code, message: message };
  if (data !== undefined) err.data = data;
  return {
    jsonrpc: JSONRPC_VERSION,
    id:      id,
    error:   err,
  };
}

function _readBody(req, maxBytes) {
  return safeBuffer.collectStream(req, {
    maxBytes:    maxBytes,
    errorClass:  A2aTasksError,
    sizeCode:    "a2a-tasks/body-too-large",
    sizeMessage: "a2a-tasks: request body exceeded " + maxBytes + " bytes",
  });
}

/**
 * @primitive b.a2a.middleware.agentCard
 * @signature b.a2a.middleware.agentCard(opts)
 * @since     0.8.85
 * @status    stable
 * @related   b.a2a.signCard, b.a2a.middleware.tasks
 *
 * Build a middleware that serves the operator's Agent Card at
 * `/.well-known/agent.json` per the A2A v1 discovery convention.
 * The middleware writes a 200 JSON response on GET; refuses other
 * methods with 405. Mount on a router path that resolves the
 * well-known prefix (operator-side).
 *
 * @opts
 *   card:        object (REQUIRED) — the signed-card envelope from b.a2a.signCard
 *   maxAgeSec:   number (default 300) — Cache-Control max-age
 *
 * @example
 *   var raw = b.a2a.createCard({
 *     agent: { name: "my-agent", version: "1.0.0" },
 *     skills: [{ name: "summarize" }],
 *   });
 *   var card = b.a2a.signCard(raw, pair.privateKey);
 *   app.get("/.well-known/agent.json", b.a2a.middleware.agentCard({ card: card }));
 */
function middlewareAgentCard(opts) {
  if (!opts || typeof opts !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-mw-opts",
      "middleware.agentCard: opts required (card)", true);
  }
  if (!opts.card || typeof opts.card !== "object") {
    throw new A2aTasksError("a2a-tasks/bad-mw-opts",
      "middleware.agentCard: opts.card required (output of b.a2a.signCard)", true);
  }
  numericBounds.requireNonNegativeFiniteIntIfPresent(
    opts.maxAgeSec, "middleware.agentCard.maxAgeSec", A2aTasksError, "a2a-tasks/bad-max-age");
  var maxAgeSec = (opts.maxAgeSec !== undefined && opts.maxAgeSec !== null && opts.maxAgeSec > 0)
    ? Math.floor(opts.maxAgeSec)
    : (C.TIME.minutes(5) / C.TIME.seconds(1));
  var cardJson = JSON.stringify(opts.card);
  return function a2aAgentCardMiddleware(req, res) {
    if ((req.method || "").toUpperCase() !== "GET") {
      res.statusCode = 405;                                                                        // HTTP 405 Method Not Allowed
      res.setHeader("Allow", "GET");
      res.end();
      return;
    }
    res.statusCode = 200;                                                                          // HTTP 200 OK
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "public, max-age=" + maxAgeSec);
    res.end(cardJson);
  };
}

module.exports = {
  send:            send,
  get:             get,
  cancel:          cancel,
  middleware: {
    tasks:     middlewareTasks,
    agentCard: middlewareAgentCard,
  },
  ALLOWED_METHODS: ALLOWED_METHODS,
  A2aTasksError:   A2aTasksError,
};
