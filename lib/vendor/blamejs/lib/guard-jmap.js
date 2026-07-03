// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardJmap
 * @nav        Guards
 * @title      Guard JMAP Request
 * @order      452
 *
 * @intro
 *   JMAP request-envelope validator (RFC 8620 JMAP Core). Validates
 *   the shape of an HTTP request body posted to `/jmap/api` and
 *   refuses requests that exceed operator caps, omit required
 *   capability declarations, or contain malformed back-references.
 *
 *   ## Request shape (RFC 8620 §3.3)
 *
 *   ```json
 *   {
 *     "using":  ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
 *     "methodCalls": [
 *       ["Mailbox/get",  { "accountId": "A1", "ids": null }, "c0"],
 *       ["Email/query",  { "filter": { "inMailbox": "#c0/list/0" } }, "c1"]
 *     ],
 *     "createdIds": null
 *   }
 *   ```
 *
 *   `using` is the set of capability URIs the request invokes; the
 *   server's `urn:ietf:params:jmap:core` is implicit. `methodCalls`
 *   is an array of 3-tuples `[methodName, args, clientId]` where
 *   `clientId` echoes back on the response for client-side
 *   correlation.
 *
 *   ## Back-reference resolution (RFC 8620 §3.7)
 *
 *   Subsequent `methodCalls` reference earlier results via
 *   `{ "resultOf": <prior-clientId>, "name": <methodName>, "path": <JSONPath> }`
 *   placeholders inside the `args` object. The validator detects
 *   back-references and caps the chain depth so a pathological
 *   chain doesn't degrade into a O(2^N) blowup.
 *
 *   ## Caps
 *
 *     - `maxCallsInRequest`         — default 32 (RFC 8620 §3.6)
 *     - `maxObjectsInGet`           — default 500
 *     - `maxObjectsInSet`           — default 500
 *     - `maxSizeRequest`            — default 10 MiB
 *     - `maxBackRefDepth`           — default 8 (we add this; spec doesn't)
 *     - `maxUsingCapabilities`      — default 32 (refuses oversize `using`)
 *
 *   Refusals emit a `urn:ietf:params:jmap:error:*` URI per
 *   RFC 8620 §3.6.1.
 *
 * @card
 *   JMAP request-envelope validator (RFC 8620 §3.3). Refuses oversize
 *   requests, capability-unknown / malformed back-reference / pipeline-
 *   bomb shapes per RFC 8620 §3.6.1 error vocabulary.
 */

var { defineClass } = require("./framework-error");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var gateContract = require("./gate-contract");

var GuardJmapError = defineClass("GuardJmapError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxCallsInRequest:     32,                                                                       // RFC 8620 §3.6 default
    maxObjectsInGet:       500,                                                                      // RFC 8620 §3.6 default
    maxObjectsInSet:       500,                                                                      // RFC 8620 §3.6 default
    maxSizeRequest:        10485760,                                                                 // 10 MiB request body cap
    maxBackRefDepth:       8,
    maxUsingCapabilities:  32,                                                                       // `using` array length cap
  },
  balanced: {
    maxCallsInRequest:     128,                                                                      // balanced call cap
    maxObjectsInGet:       1000,                                                                     // balanced object cap
    maxObjectsInSet:       1000,                                                                     // balanced object cap
    maxSizeRequest:        52428800,                                                                 // 50 MiB balanced
    maxBackRefDepth:       16,                                                                       // balanced depth
    maxUsingCapabilities:  64,                                                                       // balanced using cap
  },
  permissive: {
    maxCallsInRequest:     512,                                                                      // permissive call cap
    maxObjectsInGet:       5000,                                                                     // permissive object cap
    maxObjectsInSet:       5000,                                                                     // permissive object cap
    maxSizeRequest:        104857600,                                                                // 100 MiB permissive
    maxBackRefDepth:       32,                                                                       // permissive depth
    maxUsingCapabilities:  128,                                                                      // permissive using cap
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

// Capability URIs the server's core JMAP implementation always supports.
// Additional capabilities (mail / contacts / calendars / submission)
// the operator opts into via opts.serverCapabilities.
var CORE_CAPABILITIES = Object.freeze({
  "urn:ietf:params:jmap:core": true,
});

/**
 * @primitive b.guardJmap.validate
 * @signature b.guardJmap.validate(rawBody, opts?)
 * @since     0.9.50
 * @status    stable
 * @related   b.guardImapCommand.validate, b.safeJson.parse
 *
 * Validate a JMAP request envelope. Accepts either a raw JSON string
 * (bytes) or a pre-parsed object. Returns
 * `{ using, methodCalls, createdIds }` on success; throws
 * `GuardJmapError` with the matching `urn:ietf:params:jmap:error:*`
 * URI on refusal.
 *
 * @opts
 *   profile:               "strict" | "balanced" | "permissive",
 *   posture:               "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   serverCapabilities:    { "urn:ietf:params:jmap:mail": true, ... },
 *                          // capability URIs the server has wired; `using`
 *                          //   entries not in this set are refused with
 *                          //   urn:ietf:params:jmap:error:unknownCapability
 *
 * @example
 *   var parsed = b.guardJmap.validate(rawBody, {
 *     serverCapabilities: { "urn:ietf:params:jmap:mail": true },
 *   });
 *   // → { using: [...], methodCalls: [[methodName, args, clientId], ...] }
 */
function validate(rawBody, opts) {
  opts = opts || {};
  var profileName = typeof opts.profile === "string" ? opts.profile : DEFAULT_PROFILE;
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    profileName = COMPLIANCE_POSTURES[opts.posture];
  }
  var caps = PROFILES[profileName];
  if (!caps) {
    throw new GuardJmapError("guard-jmap/bad-profile",
      "guardJmap.validate: unknown profile '" + profileName + "'");
  }
  // Clone serverCapabilities before injecting the core capability so we
  // never mutate the operator-supplied object. mail.server.jmap.create
  // passes its shared `serverCapabilities` into every validate() call;
  // pre-fix this rewrote the operator's `urn:ietf:params:jmap:core`
  // entry to `true` after the first request, breaking the Session
  // resource's RFC 8620 §2 capability-object shape.
  var serverCaps = Object.assign({}, opts.serverCapabilities || {});
  // Always allow the core capability — the server provides it inherently.
  serverCaps["urn:ietf:params:jmap:core"] = true;

  // Parse if rawBody is a string. Cap the byte size before parsing.
  var body;
  if (typeof rawBody === "string" || Buffer.isBuffer(rawBody)) {
    var s = typeof rawBody === "string" ? rawBody : rawBody.toString("utf8");
    // Wire-protocol size cap MUST be measured in UTF-8 bytes, not
    // JavaScript UTF-16 code units. A 1 MiB cap interpreted as code
    // units lets non-ASCII payloads (emoji, CJK) past the gate at
    // 2-4× the actual byte budget — directly weakens the DoS cap.
    var byteLen = typeof rawBody === "string" ? Buffer.byteLength(s, "utf8") : rawBody.length;
    if (byteLen > caps.maxSizeRequest) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:requestTooLarge",
        "guardJmap.validate: request body " + byteLen +
        " bytes exceeds cap " + caps.maxSizeRequest);
    }
    try {
      body = safeJson.parse(s);
    } catch (e) {
      throw new GuardJmapError("guard-jmap/bad-json",
        "guardJmap.validate: body is not valid JSON: " + (e && e.message ? e.message : String(e)));
    }
  } else if (rawBody && typeof rawBody === "object") {
    body = rawBody;
  } else {
    throw new GuardJmapError("guard-jmap/bad-input",
      "guardJmap.validate: rawBody must be a JSON string, Buffer, or pre-parsed object");
  }

  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
      "guardJmap.validate: request body must be a JSON object");
  }

  if (!Array.isArray(body.using)) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
      "guardJmap.validate: `using` must be an array of capability URIs");
  }
  if (body.using.length > caps.maxUsingCapabilities) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
      "guardJmap.validate: `using` length " + body.using.length +
      " exceeds cap " + caps.maxUsingCapabilities);
  }
  for (var ui = 0; ui < body.using.length; ui += 1) {
    var cap = body.using[ui];
    if (typeof cap !== "string") {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: `using[" + ui + "]` must be a string capability URI");
    }
    if (!Object.prototype.hasOwnProperty.call(CORE_CAPABILITIES, cap) && !serverCaps[cap]) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:unknownCapability",
        "guardJmap.validate: capability '" + cap + "' not advertised by this server");
    }
  }

  if (!Array.isArray(body.methodCalls)) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
      "guardJmap.validate: `methodCalls` must be an array");
  }
  if (body.methodCalls.length === 0) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
      "guardJmap.validate: `methodCalls` must contain at least one call");
  }
  if (body.methodCalls.length > caps.maxCallsInRequest) {
    throw new GuardJmapError("urn:ietf:params:jmap:error:limit/maxCallsInRequest",
      "guardJmap.validate: " + body.methodCalls.length +
      " methodCalls exceeds cap " + caps.maxCallsInRequest);
  }

  var seenClientIds = Object.create(null);
  for (var ci = 0; ci < body.methodCalls.length; ci += 1) {
    var call = body.methodCalls[ci];
    if (!Array.isArray(call) || call.length !== 3) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "] must be a 3-tuple [name, args, clientId]");
    }
    if (typeof call[0] !== "string") {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "][0] (method name) must be a string");
    }
    if (typeof call[1] !== "object" || call[1] === null || Array.isArray(call[1])) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "][1] (args) must be an object");
    }
    if (typeof call[2] !== "string") {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "][2] (clientId) must be a string");
    }
    if (call[2].length === 0 || call[2].length > 256) {                                              // clientId length cap
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "][2] (clientId) length must be 1..256");
    }
    // Back-reference depth cap: count `resultOf` occurrences in the
    // args subtree. Pathological depth would let a client chain
    // hundreds of resolutions per call.
    var refCount = _countBackRefs(call[1], 0, caps.maxBackRefDepth);
    if (refCount === -1) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:limit/maxBackRefDepth",
        "guardJmap.validate: methodCalls[" + ci + "] back-reference depth exceeds cap " +
        caps.maxBackRefDepth);
    }
    seenClientIds[call[2]] = true;
  }

  validateOpts.optionalPlainObject(body.createdIds,
    "guardJmap.validate: `createdIds`",
    GuardJmapError, "urn:ietf:params:jmap:error:invalidArguments",
    "null or an object");

  return {
    using:       body.using,
    methodCalls: body.methodCalls,
    createdIds:  body.createdIds || null,
  };
}

// Walk args looking for back-reference markers
// (`#name`-prefixed keys per RFC 8620 §3.7 or a `resultOf` shape).
// Returns the maximum depth seen, or -1 if it exceeds maxDepth.
function _countBackRefs(node, depth, maxDepth) {
  if (depth > maxDepth) return -1;
  if (node === null || typeof node !== "object") return depth;
  if (Array.isArray(node)) {
    var maxA = depth;
    for (var i = 0; i < node.length; i += 1) {
      var d = _countBackRefs(node[i], depth + 1, maxDepth);
      if (d === -1) return -1;
      if (d > maxA) maxA = d;
    }
    return maxA;
  }
  var keys = Object.keys(node);
  if (keys.length > 1000) return -1;                                                                  // per-object key cap
  var maxO = depth;
  for (var k = 0; k < keys.length; k += 1) {
    var key = keys[k];
    var inc = (key === "resultOf" || key.charCodeAt(0) === 0x23) ? 1 : 0;                            // `#` (0x23) is the JMAP back-ref prefix
    var d2 = _countBackRefs(node[key], depth + inc, maxDepth);
    if (d2 === -1) return -1;
    if (d2 > maxO) maxO = d2;
  }
  return maxO;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "jmap",
  entry:      validate,
  errorClass: GuardJmapError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    CORE_CAPABILITIES: CORE_CAPABILITIES,
  },
});
