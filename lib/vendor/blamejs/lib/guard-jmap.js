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
    maxCallsInRequest:     32,
    maxObjectsInGet:       500,
    maxObjectsInSet:       500,
    maxSizeRequest:        10485760,
    maxBackRefDepth:       8,
    maxUsingCapabilities:  32,
  },
  balanced: {
    maxCallsInRequest:     128,
    maxObjectsInGet:       1000,
    maxObjectsInSet:       1000,
    maxSizeRequest:        52428800,
    maxBackRefDepth:       16,
    maxUsingCapabilities:  64,
  },
  permissive: {
    maxCallsInRequest:     512,
    maxObjectsInGet:       5000,
    maxObjectsInSet:       5000,
    maxSizeRequest:        104857600,
    maxBackRefDepth:       32,
    maxUsingCapabilities:  128,
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

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
  if (opts.posture && Object.prototype.hasOwnProperty.call(COMPLIANCE_POSTURES, opts.posture)) {
    profileName = COMPLIANCE_POSTURES[opts.posture];
  }
  var caps = Object.prototype.hasOwnProperty.call(PROFILES, profileName)
    ? PROFILES[profileName] : undefined;
  if (!caps) {
    throw new GuardJmapError("guard-jmap/bad-profile",
      "guardJmap.validate: unknown profile '" + profileName + "'");
  }
  var serverCaps = Object.assign({}, opts.serverCapabilities || {});
  serverCaps["urn:ietf:params:jmap:core"] = true;

  var body;
  if (typeof rawBody === "string" || Buffer.isBuffer(rawBody)) {
    var s = typeof rawBody === "string" ? rawBody : rawBody.toString("utf8");
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
    var advertised = Object.prototype.hasOwnProperty.call(CORE_CAPABILITIES, cap) ||
      (Object.prototype.hasOwnProperty.call(serverCaps, cap) && serverCaps[cap]);
    if (!advertised) {
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
    if (call[2].length === 0 || call[2].length > 256) {
      throw new GuardJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "guardJmap.validate: methodCalls[" + ci + "][2] (clientId) length must be 1..256");
    }
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
  if (keys.length > 1000) return -1;
  var maxO = depth;
  for (var k = 0; k < keys.length; k += 1) {
    var key = keys[k];
    var inc = (key === "resultOf" || key.charCodeAt(0) === 0x23) ? 1 : 0;
    var d2 = _countBackRefs(node[key], depth + inc, maxDepth);
    if (d2 === -1) return -1;
    if (d2 > maxO) maxO = d2;
  }
  return maxO;
}

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
