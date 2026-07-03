// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mcp.toolRegistry
 * @nav        MCP
 * @title      MCP Tool Registry
 * @order      500
 *
 * @intro
 *   Model Context Protocol tool registry — operator-side primitive
 *   that pairs every registered tool with a signed descriptor (so the
 *   downstream LLM can verify the tool's input/output contract hasn't
 *   been tampered with by a MCP middleman) and signs every outbound
 *   tool-call envelope (so the upstream server can verify the call
 *   actually came from this operator's MCP client, not an injected
 *   prompt that synthesized a tool call).
 *
 *   The MCP threat model surfaced by ATLAS v5.3.0 (Jan 2026) is:
 *
 *     1. Compromised MCP server — operator's LLM-side tool descriptor
 *        differs from what the server actually executes (parameter
 *        renames, type narrowing). Tool registry signs the descriptor
 *        at registration so any drift is detectable at call time.
 *     2. MCP middleman / indirect prompt injection — adversarial
 *        content reaches the LLM and convinces it to emit a synthetic
 *        tool call. Tool-call signing requires every call to carry an
 *        ML-DSA-87 signature over `{ tool, argsHash, nonce, iat, exp }`
 *        — the server-side verifier refuses unsigned calls or calls
 *        whose nonce has been seen.
 *
 *   Public surface:
 *
 *     b.mcp.toolRegistry.create({ tools, signingKey, verifyingKey? })
 *       → { register, list, get, descriptorsManifest,
 *           signCall, verifyCall }
 *
 *     - register(tool)        → stores + re-signs the descriptor
 *     - list()                → frozen array of descriptors
 *     - get(name)             → descriptor or null
 *     - descriptorsManifest() → JSON document with signature over the
 *                               full descriptor set; suitable for
 *                               operator-side attestation / shipping
 *                               alongside the MCP server URL
 *     - signCall({...})       → envelope + signature for outbound calls
 *     - verifyCall({...},opts) → verifies inbound signed envelope
 *
 *   PQC-first per the framework rule: default algorithm is ML-DSA-87.
 *   Operators using a legacy MCP peer override via opts.alg
 *   ("ed25519" | "es256" | "es384" | "es512" | "ml-dsa-44" |
 *   "ml-dsa-65" | "ml-dsa-87" | "slh-dsa-shake-256f").
 *
 *   Replay defense: `verifyCall` takes an operator-supplied
 *   `seen(jti)` callback. Same shape as `b.auth.oauth.refreshAccess
 *   Token({ seen })` — returns truthy if the nonce has been seen, false
 *   otherwise. Operator persists nonces in a TTL store (Redis,
 *   SQLite) for the call's exp window.
 *
 * @card
 *   Model Context Protocol tool registry — signed tool descriptors + signed tool-call envelopes to mitigate MCP middleman + indirect prompt injection (ATLAS v5.3.0).
 */

var nodeCrypto    = require("node:crypto");
var canonicalJson = require("./canonical-json");
var lazyRequire   = require("./lazy-require");
var validateOpts  = require("./validate-opts");
var { McpError }  = require("./framework-error");

var bCrypto = lazyRequire(function () { return require("./crypto"); });
var auditEmit = require("./audit-emit");
var C = require("./constants");

// Shared name-shape regex across mcp.js / mcp-tool-registry.js / a2a-tasks.js
// — every agent-protocol identifier follows the same RFC-3986-unreserved
// shape with a 64-char cap (MCP tool name, A2A skill name).
var TOOL_NAME_RE = /^[a-zA-Z][a-zA-Z0-9._-]{0,63}$/;   // allow:duplicate-regex — common identifier shape; consolidating would couple the protocols

var ALLOWED_ALGS = Object.freeze([
  "ed25519",
  "es256", "es384", "es512",
  "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
  "slh-dsa-shake-256f",
]);

var _emitAudit = auditEmit.emit;

function _validateAlg(alg, label) {
  if (alg === undefined || alg === null) return "ml-dsa-87";
  validateOpts.requireNonEmptyString(alg, label, McpError, "mcp/bad-alg");
  if (ALLOWED_ALGS.indexOf(alg) === -1) {
    throw new McpError("mcp/bad-alg",
      label + ": alg '" + alg + "' not in registry; allowed: " + ALLOWED_ALGS.join(", "));
  }
  return alg;
}

function _hashArgs(args) {
  // SHA3-256 over the canonical-JSON serialization of the args object.
  // Canonical-JSON ensures a server and client agree on bytes despite
  // JSON object-key ordering differences.
  var bytes = Buffer.from(canonicalJson.stringify(args === undefined ? null : args), "utf8");
  return nodeCrypto.createHash("sha3-256").update(bytes).digest("hex");
}

function _validateTool(tool, where) {
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    throw new McpError("mcp/bad-tool",
      where + ": tool must be a non-null object", true);
  }
  validateOpts.requireNonEmptyString(tool.name, where + ".name", McpError, "mcp/bad-tool-name");
  if (tool.name.length > 64 || !TOOL_NAME_RE.test(tool.name)) {                                    // MCP tool-name length cap, not byte count
    throw new McpError("mcp/bad-tool-name",
      where + ".name '" + tool.name + "' must match " + TOOL_NAME_RE);
  }
  if (!tool.inputSchema || typeof tool.inputSchema !== "object" || Array.isArray(tool.inputSchema)) {
    throw new McpError("mcp/bad-tool-schema",
      where + ".inputSchema must be a JSON-Schema-shaped object", true);
  }
  validateOpts.optionalNonEmptyString(
    tool.description, where + ".description", McpError, "mcp/bad-tool-description");
}

/**
 * @primitive b.mcp.toolRegistry.create
 * @signature b.mcp.toolRegistry.create(opts)
 * @since     0.8.85
 * @status    stable
 *
 * Build an MCP tool registry. Operator passes `tools` (array of tool
 * descriptors) and `signingKey` (PEM). Each tool gets a signed
 * descriptor blob `{ tool, alg, signature }` that the operator can
 * ship to the LLM-side runtime as an attestation. `signCall` /
 * `verifyCall` produce + verify the per-call envelope.
 *
 * Returned object is frozen at construction; tool changes go through
 * `register(tool)` which re-signs the descriptor.
 *
 * @opts
 *   tools:         array of { name, inputSchema, outputSchema?, description? }
 *   signingKey:    PEM string (required for signCall + register)
 *   verifyingKey:  PEM string (required for verifyCall on inbound calls)
 *   alg:           algorithm name (default "ml-dsa-87")
 *   ttlMs:         default call envelope TTL (default 5 minutes)
 *
 * @example
 *   var registry = b.mcp.toolRegistry.create({
 *     tools: [
 *       { name: "search", inputSchema: { type: "object", properties: {
 *         query: { type: "string" } }, required: ["query"] } },
 *     ],
 *     signingKey: pair.privateKey,
 *     verifyingKey: pair.publicKey,
 *   });
 *
 *   // Outbound call
 *   var envelope = registry.signCall({
 *     toolName: "search",
 *     args:     { query: "blamejs" },
 *   });
 *   // → { envelope: { tool, argsHash, nonce, iat, exp }, signature: "..." }
 *
 *   // Inbound verify (operator supplies a seen() callback for replay defense)
 *   var ok = registry.verifyCall(envelope, {
 *     seen: function (nonce) { return nonceStore.has(nonce); },
 *   });
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new McpError("mcp/bad-registry-opts",
      "toolRegistry.create: opts required (tools + signingKey)", true);
  }
  validateOpts.shape(opts, {
    tools: function (value) {
      if (!Array.isArray(value)) {
        throw new McpError("mcp/bad-registry-opts",
          "toolRegistry.create: opts.tools must be an array", true);
      }
    },
    signingKey:   { rule: "required-string", code: "mcp/bad-signing-key",   label: "toolRegistry.create.signingKey" },
    verifyingKey: { rule: "optional-string", code: "mcp/bad-verifying-key", label: "toolRegistry.create.verifyingKey" },
    alg: function (value) {
      // undefined → default applied below; any present value is registry-checked.
      _validateAlg(value, "toolRegistry.create.alg");
    },
    ttlMs: function (value) {
      // undefined → registry default applied below; any present value must be a
      // finite millisecond count at or above the 1-second floor.
      if (value === undefined) return;
      if (typeof value !== "number" || !isFinite(value) || value < 1000) {                         // minimum-ttl threshold (1 second), not bytes
        throw new McpError("mcp/bad-ttl",
          "toolRegistry.create.ttlMs must be >= 1000 ms", true);
      }
    },
  }, "toolRegistry.create", McpError, "mcp/bad-registry-opts");
  var alg = _validateAlg(opts.alg, "toolRegistry.create.alg");
  var defaultTtlMs = opts.ttlMs !== undefined ? opts.ttlMs : C.TIME.minutes(5);

  var signingKey = opts.signingKey;
  var verifyingKey = opts.verifyingKey || null;
  var tools = Object.create(null);

  function _signDescriptor(tool) {
    var payload = canonicalJson.stringify({
      tool:        tool.name,
      description: tool.description || "",
      inputSchema:  tool.inputSchema,
      outputSchema: tool.outputSchema || null,
      alg:         alg,
    });
    var sig = bCrypto().sign(Buffer.from(payload, "utf8"), signingKey);
    return {
      tool:         tool.name,
      description:  tool.description || "",
      inputSchema:  tool.inputSchema,
      outputSchema: tool.outputSchema || null,
      alg:          alg,
      signature:    sig.toString("base64"),
    };
  }

  function register(tool) {
    _validateTool(tool, "toolRegistry.register");
    var descriptor = _signDescriptor(tool);
    tools[tool.name] = Object.freeze(descriptor);
    _emitAudit("mcp.tool_registry.registered",
      { tool: tool.name, alg: alg });
    return descriptor;
  }

  // Bootstrap-register every tool in opts.tools at construction.
  for (var i = 0; i < opts.tools.length; i += 1) {
    register(opts.tools[i]);
  }

  function list() {
    var names = Object.keys(tools).sort();   // allow:bare-canonicalize-walk — deterministic-ordering of registered-tool names, not JSON canonicalization
    var out = new Array(names.length);
    for (var i2 = 0; i2 < names.length; i2 += 1) {
      out[i2] = tools[names[i2]];
    }
    return Object.freeze(out);
  }

  function get(name) {
    if (typeof name !== "string" || name.length === 0) return null;
    return tools[name] || null;
  }

  function descriptorsManifest() {
    var rows = list();
    var manifestBody = canonicalJson.stringify({
      alg:     alg,
      tools:   rows.map(function (d) {
        return {
          tool:         d.tool,
          inputSchema:  d.inputSchema,
          outputSchema: d.outputSchema,
        };
      }),
      issuedAt: new Date().toISOString(),
    });
    var sig = bCrypto().sign(Buffer.from(manifestBody, "utf8"), signingKey);
    return {
      body:      manifestBody,
      signature: sig.toString("base64"),
      alg:       alg,
    };
  }

  /**
   * @primitive b.mcp.toolRegistry.create.signCall
   * @signature b.mcp.toolRegistry.create.signCall(opts)
   * @since     0.8.85
   *
   * Build + sign an outbound tool-call envelope. Returns
   * `{ envelope, signature, alg }`. The envelope shape is
   * `{ tool, argsHash, nonce, iat, exp }` where `argsHash` is the
   * SHA3-256 hex digest of canonical-JSON(args) so the server can
   * verify the args bytes match without including them in the
   * signature (smaller envelope, no double-encoding).
   *
   * @opts
   *   toolName: string,   // required — must match a registered tool
   *   args:     object,   // tool input arguments
   *   nonce:    string,   // optional — caller-supplied; default 128-bit random hex
   *   ttlMs:    number,   // optional — overrides registry default
   *
   * @example
   *   var env = registry.signCall({
   *     toolName: "search",
   *     args:     { query: "blamejs" },
   *   });
   *   // env.envelope.tool      === "search"
   *   // env.envelope.argsHash  === <hex>
   *   // env.envelope.nonce     === <hex>
   *   // env.envelope.iat       === ISO timestamp
   *   // env.envelope.exp       === ISO timestamp (iat + ttlMs)
   */
  function signCall(callOpts) {
    if (!callOpts || typeof callOpts !== "object") {
      throw new McpError("mcp/bad-call-opts",
        "signCall: opts required (toolName + args)", true);
    }
    validateOpts.requireNonEmptyString(
      callOpts.toolName, "signCall.toolName", McpError, "mcp/bad-tool-name");
    if (!tools[callOpts.toolName]) {
      throw new McpError("mcp/unregistered-tool",
        "signCall: tool '" + callOpts.toolName + "' not registered", true);
    }
    var ttlMs = callOpts.ttlMs !== undefined ? callOpts.ttlMs : defaultTtlMs;
    if (typeof ttlMs !== "number" || !isFinite(ttlMs) || ttlMs < 1000) {                          // minimum-ttl threshold (1 second), not bytes
      throw new McpError("mcp/bad-ttl",
        "signCall: ttlMs must be >= 1000 ms", true);
    }
    var nonce = typeof callOpts.nonce === "string" && callOpts.nonce.length > 0
      ? callOpts.nonce
      : bCrypto().generateToken(16);                                                                // 128-bit nonce, not byte arithmetic on a payload
    var iat = new Date();
    var exp = new Date(iat.getTime() + ttlMs);
    var envelope = {
      tool:     callOpts.toolName,
      argsHash: _hashArgs(callOpts.args),
      nonce:    nonce,
      iat:      iat.toISOString(),
      exp:      exp.toISOString(),
    };
    var payload = Buffer.from(canonicalJson.stringify(envelope), "utf8");
    var sig = bCrypto().sign(payload, signingKey);
    _emitAudit("mcp.tool_registry.call_signed",
      { tool: envelope.tool, nonce: nonce, alg: alg });
    return {
      envelope:  envelope,
      signature: sig.toString("base64"),
      alg:       alg,
    };
  }

  /**
   * @primitive b.mcp.toolRegistry.create.verifyCall
   * @signature b.mcp.toolRegistry.create.verifyCall(signedCall, opts?)
   * @since     0.8.85
   *
   * Verify an inbound tool-call envelope. Required `signedCall` shape
   * is `{ envelope, signature, alg }`. Returns `true` on success;
   * throws `mcp/call-verify-failed` (or a more specific code) on any
   * failure:
   *
   *   - mcp/call-verify-failed             — signature mismatch
   *   - mcp/call-expired                   — `exp` past current wall clock
   *   - mcp/call-replay                    — seen(nonce) returned truthy
   *   - mcp/call-unregistered-tool         — envelope.tool not in registry
   *   - mcp/call-args-mismatch             — argsHash doesn't match the supplied args
   *
   * Replay defense: operator supplies `opts.seen(nonce) → boolean`.
   * Common shape: `Map.has(nonce)` against an in-memory cache with
   * TTL matching the envelope's `exp - iat`. Without a seen()
   * callback, replay defense is skipped (caller's choice).
   *
   * @opts
   *   args:    object,                            // optional — when present, argsHash is checked
   *   seen:    function (nonce) → boolean,        // optional — replay-defense callback
   *   nowMs:   number,                            // optional — override Date.now() (testing only)
   *
   * @example
   *   try {
   *     var ok = registry.verifyCall(signedFromClient, {
   *       args: actualArgs,
   *       seen: function (nonce) { return nonceCache.has(nonce); },
   *     });
   *   } catch (e) {
   *     if (e.code === "mcp/call-replay")   return refuseReplay();
   *     if (e.code === "mcp/call-expired")  return refuseExpired();
   *     throw e;
   *   }
   */
  function verifyCall(signedCall, verifyOpts) {
    if (!signedCall || typeof signedCall !== "object") {
      throw new McpError("mcp/bad-signed-call",
        "verifyCall: signedCall must be an object", true);
    }
    if (!signedCall.envelope || typeof signedCall.envelope !== "object") {
      throw new McpError("mcp/bad-signed-call",
        "verifyCall: signedCall.envelope required", true);
    }
    validateOpts.requireNonEmptyString(
      signedCall.signature, "verifyCall.signature", McpError, "mcp/bad-signature");
    var env = signedCall.envelope;
    validateOpts.requireNonEmptyString(env.tool, "verifyCall.envelope.tool", McpError, "mcp/bad-tool-name");
    validateOpts.requireNonEmptyString(env.nonce, "verifyCall.envelope.nonce", McpError, "mcp/bad-nonce");
    validateOpts.requireNonEmptyString(env.argsHash, "verifyCall.envelope.argsHash", McpError, "mcp/bad-args-hash");
    validateOpts.requireNonEmptyString(env.iat, "verifyCall.envelope.iat", McpError, "mcp/bad-iat");
    validateOpts.requireNonEmptyString(env.exp, "verifyCall.envelope.exp", McpError, "mcp/bad-exp");

    if (!tools[env.tool]) {
      _emitAudit("mcp.tool_registry.call_unregistered",
        { tool: env.tool, nonce: env.nonce }, "denied");
      throw new McpError("mcp/call-unregistered-tool",
        "verifyCall: tool '" + env.tool + "' not registered");
    }

    var nowMs = (verifyOpts && typeof verifyOpts.nowMs === "number") ? verifyOpts.nowMs : Date.now();
    var expMs = Date.parse(env.exp);
    if (!isFinite(expMs)) {
      throw new McpError("mcp/bad-exp",
        "verifyCall: envelope.exp is not a valid ISO timestamp");
    }
    if (nowMs > expMs) {
      _emitAudit("mcp.tool_registry.call_expired",
        { tool: env.tool, nonce: env.nonce, exp: env.exp }, "denied");
      throw new McpError("mcp/call-expired",
        "verifyCall: envelope expired at " + env.exp);
    }

    // Replay-defense — operator-supplied seen() callback.
    if (verifyOpts && typeof verifyOpts.seen === "function" && verifyOpts.seen(env.nonce)) {
      _emitAudit("mcp.tool_registry.call_replay",
        { tool: env.tool, nonce: env.nonce }, "denied");
      throw new McpError("mcp/call-replay",
        "verifyCall: nonce '" + env.nonce + "' already seen");
    }

    // Optional args-hash binding when operator passes the raw args.
    if (verifyOpts && verifyOpts.args !== undefined) {
      var expected = _hashArgs(verifyOpts.args);
      if (expected !== env.argsHash) {
        _emitAudit("mcp.tool_registry.call_args_mismatch",
          { tool: env.tool, nonce: env.nonce }, "denied");
        throw new McpError("mcp/call-args-mismatch",
          "verifyCall: args don't match envelope.argsHash");
      }
    }

    // Signature verify.
    if (!verifyingKey) {
      throw new McpError("mcp/no-verifying-key",
        "verifyCall: registry was created without a verifyingKey; verifyCall is inbound-only and requires one");
    }
    var payload = Buffer.from(canonicalJson.stringify(env), "utf8");
    var sigBuf;
    try { sigBuf = Buffer.from(signedCall.signature, "base64"); }
    catch (_e) {
      throw new McpError("mcp/bad-signature",
        "verifyCall: signature not valid base64");
    }
    var ok;
    try { ok = bCrypto().verify(payload, sigBuf, verifyingKey); }
    catch (verifyErr) {
      _emitAudit("mcp.tool_registry.call_verify_error",
        { tool: env.tool, nonce: env.nonce, error: String(verifyErr.message || verifyErr) }, "denied");
      throw new McpError("mcp/call-verify-failed",
        "verifyCall: " + (verifyErr.message || verifyErr));
    }
    if (!ok) {
      _emitAudit("mcp.tool_registry.call_verify_failed",
        { tool: env.tool, nonce: env.nonce }, "denied");
      throw new McpError("mcp/call-verify-failed",
        "verifyCall: signature did not verify against registry's verifyingKey");
    }
    _emitAudit("mcp.tool_registry.call_verified",
      { tool: env.tool, nonce: env.nonce });
    return true;
  }

  return Object.freeze({
    register:            register,
    list:                list,
    get:                 get,
    descriptorsManifest: descriptorsManifest,
    signCall:            signCall,
    verifyCall:          verifyCall,
    alg:                 alg,
  });
}

module.exports = {
  create:       create,
  ALLOWED_ALGS: ALLOWED_ALGS,
};
