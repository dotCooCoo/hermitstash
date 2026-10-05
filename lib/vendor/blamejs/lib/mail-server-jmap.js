// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.jmap
 * @nav        Mail
 * @title      Mail JMAP Server
 * @order      548
 *
 * @intro
 *   JMAP Core (RFC 8620) + JMAP Mail (RFC 8621) listener. Where IMAP
 *   is a TCP text-protocol with a connection state-machine, JMAP is
 *   HTTP-mounted JSON-RPC — operators mount the handler under their
 *   existing `b.router` / `b.createApp` and the JMAP semantics ride
 *   the HTTP request lifecycle (auth → body parse → handler →
 *   response).
 *
 *   ## Public surface
 *
 *   ```js
 *   var jmap = b.mail.server.jmap.create({
 *     mailStore:           b.mailStore.create({ backend: b.db }),
 *     methods: {
 *       "Mailbox/get":     async function (actor, args) {...},
 *       "Email/query":     async function (actor, args) {...},
 *       "Email/get":       async function (actor, args) {...},
 *     },
 *     serverCapabilities: {
 *       "urn:ietf:params:jmap:mail":       { maxMailboxesPerEmail: null },
 *       "urn:ietf:params:jmap:submission": null,
 *     },
 *   });
 *
 *   // Mount on the framework's router:
 *   app.use("/.well-known/jmap", jmap.discoveryHandler);
 *   app.use("/jmap/session",     b.middleware.bearerAuth(...), jmap.sessionHandler);
 *   app.use("/jmap/api",         b.middleware.bearerAuth(...), jmap.apiHandler);
 *   ```
 *
 *   The listener owns the request envelope (`b.guardJmap.validate`),
 *   back-reference resolution (RFC 8620 §3.7), the per-call dispatch,
 *   and the standard error mapping (RFC 8620 §3.6.1). In a result
 *   reference path, `*` applies the tokens after it to every item of
 *   the array and flattens array results into one array, so
 *   `/list/*<!---->/emailIds` over a `Thread/get` response yields the
 *   message ids; a path no item satisfies fails the call with
 *   `invalidResultReference`, an array index follows the RFC 6901
 *   grammar, and an argument given both directly and as `#name` is
 *   `invalidArguments`. Operators supply the method implementations
 *   themselves: Mailbox, Email, Thread, SearchSnippet, Identity and
 *   EmailSubmission are not implemented here.
 *
 *   ## Capability discovery (RFC 8620 §2)
 *
 *   GET `/.well-known/jmap` redirects to the session resource per
 *   §2.2. GET `/jmap/session` returns the session object with the
 *   server's capabilities, account list (operator-supplied via
 *   `opts.accountsFor(actor)`), and endpoint URLs.
 *
 *   ## Request shape (RFC 8620 §3.3)
 *
 *   POST `/jmap/api` with body:
 *
 *   ```json
 *   {
 *     "using":       ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
 *     "methodCalls": [
 *       ["Mailbox/get", { "accountId": "A1" }, "c0"],
 *       ["Email/query", { "filter": { "inMailbox": "#c0/list/0/id" } }, "c1"]
 *     ]
 *   }
 *   ```
 *
 *   Response shape:
 *
 *   ```json
 *   {
 *     "methodResponses": [
 *       ["Mailbox/get", { ... }, "c0"],
 *       ["Email/query", { ... }, "c1"]
 *     ],
 *     "sessionState": "<opaque-token>"
 *   }
 *   ```
 *
 *   ## Caps (RFC 8620 §3.6)
 *
 *   `b.guardJmap.validate` applies `maxCallsInRequest`, `maxSizeRequest`,
 *   `maxUsingCapabilities` and `maxBackRefDepth` to the request envelope.
 *   `dispatch` applies `maxObjectsInGet` to a `/get` call's `ids` and
 *   `maxObjectsInSet` to the combined `create`, `update` and `destroy` of a
 *   `/set` or `/copy` call, after result references resolve, answering an
 *   over-cap call with `requestTooLarge` before the handler runs. The
 *   session's `urn:ietf:params:jmap:core` capability publishes all of them.
 *   Per-account method-call concurrent cap via `b.mail.server.rateLimit`
 *   when wired.
 *
 *   ## Error vocabulary (RFC 8620 §3.6)
 *
 *   A refused request (§3.6.1) is answered with an
 *   `application/problem+json` body carrying `type`, `status` and
 *   `detail`, and no `methodResponses`. The type is one of:
 *
 *     - `urn:ietf:params:jmap:error:unknownCapability`
 *     - `urn:ietf:params:jmap:error:notJSON`
 *     - `urn:ietf:params:jmap:error:notRequest`
 *     - `urn:ietf:params:jmap:error:limit`, with a `limit` member naming
 *       the cap reached (`maxSizeRequest`, `maxCallsInRequest`,
 *       `maxUsingCapabilities`, `maxBackRefDepth`)
 *     - `urn:ietf:params:jmap:error:forbidden` (401)
 *     - `urn:ietf:params:jmap:error:serverFail` (500, opaque last-resort)
 *
 *   A method error (§3.6.2) replaces that call's response with
 *   `[ "error", { "type": "<name>", ... }, "<clientId>" ]`, where the
 *   type is the bare name: `unknownMethod`, `invalidArguments`,
 *   `invalidResultReference`, `accountNotFound`, `serverFail`, and the
 *   RFC 8621 set errors a handler returns or throws.
 *
 *   ## Beyond Core + Mail, this also ships
 *
 *   - **Push channel (RFC 8887)** — `eventSourceHandler` (SSE) and
 *     `webSocketHandler` (WebSocket, with `StateChange` push).
 *   - **Blob upload/download (RFC 8620 §6)** — `uploadHandler` /
 *     `downloadHandler`, routing uploads through the guard-* family.
 *   - **EmailSubmission/set (RFC 8621 §7.5)** — `emailSubmissionSetHandler`,
 *     composing `b.mail.send.deliver`.
 *
 *   ## What v1 does NOT ship
 *
 *   - **Calendars / Contacts (RFC 9610)**, **Sieve (RFC 9661)**,
 *     **MDN (RFC 9007)** — opt-in capabilities.
 *
 * @card
 *   JMAP Core (RFC 8620) + JMAP Mail (RFC 8621) listener. HTTP-mounted
 *   JSON-RPC. Composes b.guardJmap (request-envelope validator) +
 *   operator-supplied method handlers + b.mailStore. Per-account back-
 *   reference resolution (RFC 8620 §3.7) + standard error vocabulary
 *   (RFC 8620 §3.6.1) handled at the listener boundary.
 */

var lazyRequire = require("./lazy-require");
var C = require("./constants");
var cdnCacheControl = require("./cdn-cache-control");
var bCrypto = require("./crypto");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var websocket = require("./websocket");
var validateOpts = require("./validate-opts");
var guardJmap = require("./guard-jmap");
var safeMime = require("./safe-mime");
var staticServe = require("./static");
var mailServerRegistry = require("./mail-server-registry");
var mailServerNet = require("./mail-server-net");
var requestHelpers = require("./request-helpers");
var structuredFields = require("./structured-fields");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var auditEmit = require("./audit-emit");
var pick = require("./pick");

var MailServerJmapError = defineClass("MailServerJmapError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var MAX_MEDIA_TYPE_BYTES = 320;

var TOO_MANY_REQUESTS_STATUS = 429;

var REQUEST_PROBLEM_STATUS = Object.freeze({
  "urn:ietf:params:jmap:error:unknownCapability": 400,
  "urn:ietf:params:jmap:error:notJSON":           400,
  "urn:ietf:params:jmap:error:notRequest":        400,
  "urn:ietf:params:jmap:error:limit":             400,
  "urn:ietf:params:jmap:error:forbidden":         401,
  "urn:ietf:params:jmap:error:serverFail":        500,
  "urn:ietf:params:jmap:error:serverUnavailable": 503,
});

var PROBLEM_JSON_TYPE = "application/problem+json; charset=utf-8";

var METHOD_ERROR_PREFIX = "urn:ietf:params:jmap:error:";

var MAX_JMAP_ID_CHARS = 255;
var JMAP_ID_CHARS_RE  = /^[A-Za-z0-9_-]{1,255}$/;

var METHOD_ERROR_NAMES = Object.freeze({
  serverUnavailable: 1, serverFail: 1, serverPartialFail: 1, unknownMethod: 1,
  invalidArguments: 1, invalidResultReference: 1, forbidden: 1, accountNotFound: 1,
  accountNotSupportedByMethod: 1, accountReadOnly: 1, requestTooLarge: 1,
  stateMismatch: 1, cannotCalculateChanges: 1, tooManyChanges: 1, anchorNotFound: 1,
  unsupportedSort: 1, unsupportedFilter: 1, invalidPatch: 1, willDestroy: 1,
  invalidProperties: 1, singleton: 1, alreadyExists: 1, notFound: 1, overQuota: 1,
  tooLarge: 1, rateLimit: 1, mailboxHasChild: 1, mailboxHasEmail: 1, blobNotFound: 1,
  tooManyKeywords: 1, tooManyMailboxes: 1, invalidEmail: 1, invalidRecipients: 1,
  forbiddenFrom: 1, forbiddenMailFrom: 1, forbiddenToSend: 1,
  fromAccountNotFound: 1, toAccountNotFound: 1, fromAccountNotSupportedByMethod: 1,
});

function methodErrorName(type) {
  if (typeof type !== "string" || type.length === 0) return null;
  var prefixed = type.indexOf(METHOD_ERROR_PREFIX) === 0;
  var bare = prefixed ? type.slice(METHOD_ERROR_PREFIX.length) : type;
  var slash = bare.indexOf("/");
  if (slash !== -1) bare = bare.slice(0, slash);
  if (Object.prototype.hasOwnProperty.call(METHOD_ERROR_NAMES, bare)) return bare;
  if (!prefixed || bare.length === 0 || bare.length > MAX_METHOD_ERROR_NAME_CHARS) return null;
  return METHOD_ERROR_NAME_RE.test(bare) ? bare : null;
}

var MAX_METHOD_ERROR_NAME_CHARS = 128;
var METHOD_ERROR_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]*$/;

function _methodError(type, description) {
  return { type: methodErrorName(type) || "serverFail", description: description };
}

var METHOD_ERROR_MEMBERS = Object.freeze({ type: 1, description: 1, properties: 1 });

function _resultIsMethodError(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return false;
  if (methodErrorName(result.type) === null) return false;
  if (typeof result.type === "string" &&
      result.type.indexOf(METHOD_ERROR_PREFIX) === 0) {
    return true;
  }
  var keys = Object.keys(result);
  for (var i = 0; i < keys.length; i += 1) {
    if (!Object.prototype.hasOwnProperty.call(METHOD_ERROR_MEMBERS, keys[i])) return false;
  }
  return true;
}

var DEFAULT_BLOB_BYTES = C.BYTES.mib(50);
var DEFAULT_CONCURRENT_UPLOAD = 4;
var DEFAULT_CONCURRENT_REQUESTS = 4;
var DEFAULT_COLLATIONS = Object.freeze(["i;ascii-numeric", "i;ascii-casemap", "i;octet"]);

function _refuseDisagreeingCoreCapability(supplied, enforced) {
  if (!supplied || typeof supplied !== "object") return;
  var enforcedKeys = Object.keys(enforced);
  for (var i = 0; i < enforcedKeys.length; i += 1) {
    var k = enforcedKeys[i];
    if (supplied[k] === undefined) continue;
    if (JSON.stringify(supplied[k]) === JSON.stringify(enforced[k])) continue;
    throw new MailServerJmapError("mail-server-jmap/core-capability-disagrees",
      "mail.server.jmap.create: serverCapabilities['urn:ietf:params:jmap:core']." + k +
      " is " + JSON.stringify(supplied[k]) + ", but this listener enforces " +
      JSON.stringify(enforced[k]) + " (set the matching opts instead)");
  }
}

function _decodedPathSegment(segment) {
  var raw = segment === undefined || segment === null ? "" : String(segment);
  try { return decodeURIComponent(raw); }
  catch (_e) { return raw; }
}

var NAMES_IDS_REQUESTED  = /\/(?:get|parse)$/;
var NAMES_OBJECTS_WRITTEN = /\/(?:set|copy|import)$/;

var ID_ARGUMENT_RE = /^(?:ids|[a-z][A-Za-z0-9]*Ids)$/;
var MAX_ARGUMENT_NAME_CHARS = 64;
var MAX_GROUP_NESTING = 4;

function _idArgumentsOf(args) {
  var out = [];
  var keys = Object.keys(args);
  for (var i = 0; i < keys.length; i += 1) {
    var key = keys[i];
    if (key.length > MAX_ARGUMENT_NAME_CHARS || !ID_ARGUMENT_RE.test(key)) continue;
    out.push(key);
  }
  return out;
}

function _objectsNamed(args, keys) {
  var total = 0;
  for (var i = 0; i < keys.length; i += 1) {
    var value = args[keys[i]];
    if (Array.isArray(value)) total += value.length;
    else if (value && typeof value === "object") total += Object.keys(value).length;
  }
  return total;
}

var ARRAY_INDEX_RE = /^(?:0|[1-9][0-9]{0,14})$/;
var MAX_ARRAY_INDEX_CHARS = 15;
var EXPANDED_ELEMENT_MIN_BYTES = 16;

var ATEXT_EXCLUDED = Object.freeze({
  "@": 1, "<": 1, ">": 1, ",": 1, ";": 1, ":": 1, "\\": 1,
  "\"": 1, "[": 1, "]": 1, "(": 1, ")": 1,
});

var ATOM_BOUNDARY = Object.freeze({
  "@": 1, ".": 1, "<": 1, ">": 1, ",": 1, ";": 1, ":": 1,
  "\"": 1, "[": 1, "]": 1, "(": 1, ")": 1,
});

function _isAtomBoundary(ch) {
  return Object.prototype.hasOwnProperty.call(ATOM_BOUNDARY, ch);
}

var MEDIA_TYPE_RE =
  /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+(?:[ \t]*;[ \t]*[A-Za-z0-9!#$%&'*+.^_`|~-]+=(?:[A-Za-z0-9!#$%&'*+.^_`|~-]+|"(?:[\t\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\t\x20-\x7E])*"))*$/;   // allow:regex-no-length-cap — anchored, length bounded by the caller before this runs
void C;

/**
 * @primitive b.mail.server.jmap.create
 * @signature b.mail.server.jmap.create(opts)
 * @since     0.9.50
 * @status    stable
 * @related   b.mail.server.imap.create, b.guardJmap.validate, b.mailStore.create
 *
 * Build a JMAP Core + JMAP Mail listener. Returns a handle exposing
 * `apiHandler` / `sessionHandler` / `discoveryHandler` (Express-style
 * `(req, res, next)` functions) and `dispatch(actor, body)` for
 * operators with a non-Express transport.
 *
 * @opts
 *   mailStore:           b.mailStore handle (operator-supplied backend),
 *   methods:             { "<Type>/<verb>": async fn(actor, args, ctx) },
 *                         // operator-supplied JMAP method handlers
 *   serverCapabilities:  { "<URI>": <capability-record> },
 *                         // capabilities the server advertises beyond core
 *   accountsFor:         async function (actor) → { primaryAccounts, accounts },
 *                         // operator-supplied accountId enumeration
 *   webSocket:           boolean,   // default true — false stops advertising the
 *                         // RFC 8887 WebSocket transport (capability and the
 *                         // top-level webSocketUrl alias), for a deployment
 *                         // that has not wired the upgrade handler
 *   webSocketUrl:        string,    // default "/jmap/ws" — where the upgrade lives
 *   webSocketMaxMessageBytes: number, // default: the profile's maxSizeRequest
 *   profile:             "strict" | "balanced" | "permissive",
 *   posture:             "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   maxBlobBytes:        number,   // positive integer; default 50 MiB, published
 *                         // as maxSizeUpload
 *   maxConcurrentUpload: number,   // default: 4
 *   maxConcurrentRequests: number, // default: 4
 *   actorKey:            function, // (actor) => string naming the principal, for a
 *                         // deployment whose actors carry none of id, userId,
 *                         // username, sub, principalId, email
 *   collationAlgorithms: [string], // default: RFC 4790 i;ascii-numeric,
 *                         // i;ascii-casemap, i;octet
 *   audit:               b.audit                                       // optional
 *
 * @example
 *   var jmap = b.mail.server.jmap.create({
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *     methods: {
 *       "Mailbox/get": async function (actor, args) {
 *         return { accountId: args.accountId, list: [], notFound: [] };
 *       },
 *     },
 *     serverCapabilities: { "urn:ietf:params:jmap:mail": {} },
 *     accountsFor: async function (actor) {
 *       return {
 *         primaryAccounts: { "urn:ietf:params:jmap:mail": "A1" },
 *         accounts: { A1: { name: actor.username } },
 *       };
 *     },
 *   });
 *
 *   app.post("/jmap/api", b.middleware.bearerAuth({ verify: verify }), jmap.apiHandler);
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.jmap.create",
    MailServerJmapError, "mail-server-jmap/bad-opts");
  if (!opts.mailStore) {
    throw new MailServerJmapError("mail-server-jmap/no-mail-store",
      "mail.server.jmap.create: mailStore is required (compose b.mailStore.create({ backend: ... }))");
  }
  if (typeof opts.methods !== "object" || opts.methods === null || Array.isArray(opts.methods)) {
    throw new MailServerJmapError("mail-server-jmap/no-methods",
      "mail.server.jmap.create: opts.methods must be an object mapping method-name → async fn(actor, args, ctx)");
  }
  if (typeof opts.accountsFor !== "function") {
    throw new MailServerJmapError("mail-server-jmap/no-accounts-for",
      "mail.server.jmap.create: opts.accountsFor(actor) async function is required for the session resource");
  }
  var profile = opts.profile || DEFAULT_PROFILE;
  var posture = opts.posture || null;
  var serverCapabilities = opts.serverCapabilities || {};
  var limits = guardJmap.limitsFor({ profile: profile, posture: posture });
  _refusePositiveIntegerOpt(opts.maxConcurrentRequests, "maxConcurrentRequests");
  _refusePositiveIntegerOpt(opts.maxConcurrentUpload, "maxConcurrentUpload");
  _refuseBlobCap(opts.maxBlobBytes);
  validateOpts.optionalPositiveInt(opts.webSocketMaxMessageBytes,
    "mail.server.jmap.create: opts.webSocketMaxMessageBytes (the largest WebSocket " +
    "message this listener buffers, applied by the transport before dispatch reaches " +
    "the profile's maxSizeRequest, so a value it cannot apply leaves the frame unbounded)",
    MailServerJmapError, "mail-server-jmap/bad-websocket-cap");
  validateOpts.optionalNonEmptyString(opts.webSocketUrl,
    "mail.server.jmap.create: opts.webSocketUrl (the path the session advertises for " +
    "the RFC 8887 upgrade)",
    MailServerJmapError, "mail-server-jmap/bad-websocket-url");
  _refuseCollations(opts.collationAlgorithms);
  var maxBlobBytes = opts.maxBlobBytes === undefined || opts.maxBlobBytes === null
    ? DEFAULT_BLOB_BYTES : opts.maxBlobBytes;
  var webSocketMaxMessageBytes = opts.webSocketMaxMessageBytes || limits.maxSizeRequest;
  var coreCapability = Object.freeze({
    maxSizeUpload:         maxBlobBytes,
    maxConcurrentUpload:   opts.maxConcurrentUpload   || DEFAULT_CONCURRENT_UPLOAD,
    maxSizeRequest:        limits.maxSizeRequest,
    maxConcurrentRequests: opts.maxConcurrentRequests || DEFAULT_CONCURRENT_REQUESTS,
    maxCallsInRequest:     limits.maxCallsInRequest,
    maxObjectsInGet:       limits.maxObjectsInGet,
    maxObjectsInSet:       limits.maxObjectsInSet,
    collationAlgorithms:   Object.freeze(
      (opts.collationAlgorithms || DEFAULT_COLLATIONS).slice()),
  });
  _refuseDisagreeingCoreCapability(serverCapabilities["urn:ietf:params:jmap:core"],
    coreCapability);
  validateOpts.optionalFunction(opts.actorKey,
    "mail.server.jmap.create: opts.actorKey (actor) => string naming the principal, " +
    "for a deployment whose actors carry none of the fields this listener reads",
    MailServerJmapError, "mail-server-jmap/bad-actor-key");
  function _actorSlotKeyOrNull(actor, op) {
    try { return requestHelpers.actorIdentityKey(actor, { actorKey: opts.actorKey }); }
    catch (e) {
      _emit("mail.server.jmap.actor_key_threw",
        { op: op, error: (e && e.message) || String(e) }, "failure");
      return null;
    }
  }

  var requestSlots = _concurrencySlots(coreCapability.maxConcurrentRequests);
  var uploadSlots  = _concurrencySlots(coreCapability.maxConcurrentUpload);
  validateOpts.optionalBoolean(opts.webSocket,
    "mail.server.jmap.create: opts.webSocket (false stops advertising the RFC 8887 " +
    "WebSocket transport, for a deployment that has not wired the upgrade handler)",
    MailServerJmapError, "mail-server-jmap/bad-websocket");
  var webSocketEnabled = opts.webSocket !== false;

  var LEGACY_JMAP_BYTES = 10 * 1024 * 1024;                                                          // allow:raw-byte-literal — 10 MiB legacy auto-budget for JMAP methods
  var LEGACY_JMAP_MS    = 30 * 1000;                                                                 // allow:raw-time-literal — 30s legacy auto-budget
  var _legacyDeprecationEmitted = false;
  var defaults = {};
  var methodNames = Object.keys(opts.methods);
  for (var mi = 0; mi < methodNames.length; mi += 1) {
    var mname = methodNames[mi];
    if (typeof opts.methods[mname] !== "function") continue;
    defaults[mname] = {
      fn:               opts.methods[mname],
      maxHandlerBytes:  LEGACY_JMAP_BYTES,
      maxHandlerMs:     LEGACY_JMAP_MS,
      allowExperimental: true,
    };
  }
  var registry = mailServerRegistry.create({
    protocol:      "jmap",
    defaults:      defaults,
    overrides:     opts.overrides || {},
    tenantScope:   opts.tenantScope   || null,
    agentTenantId: opts.agentTenantId || null,
  });
  var sessionState = bCrypto.generateToken(16);

  var _emit = auditEmit.dualEmitter(opts);

  function _movesThePrototype(key) {
    return pick.movesThePrototype(key);
  }

  function _resolveBackRefs(args, priorResponses, budget) {
    if (args === null || typeof args !== "object") return args;
    if (Array.isArray(args)) {
      var out = [];
      for (var i = 0; i < args.length; i += 1) {
        out.push(_resolveBackRefs(args[i], priorResponses, budget));
      }
      return out;
    }
    var obj = {};
    var keys = Object.keys(args);
    for (var d = 0; d < keys.length; d += 1) {
      if (keys[d].charCodeAt(0) !== 0x23) continue;
      var plain = keys[d].slice(1);
      if (Object.prototype.hasOwnProperty.call(args, plain)) {
        throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidArguments",
          "argument '" + plain + "' is given both directly and as a result reference '#" +
          plain + "'; RFC 8620 section 3.7 allows one or the other");
      }
    }
    for (var k = 0; k < keys.length; k += 1) {
      var key = keys[k];
      var val = args[key];
      if (key.charCodeAt(0) === 0x23) {
        var targetKey = key.slice(1);
        if (_movesThePrototype(targetKey)) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "back-ref `#" + targetKey + "` names a reserved property");
        }
        if (!val || typeof val !== "object" || Array.isArray(val) ||
            typeof val.resultOf !== "string" || typeof val.name !== "string" ||
            typeof val.path !== "string") {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "back-ref `#" + targetKey + "` malformed (expected { resultOf, name, path })");
        }
        var src = priorResponses[val.resultOf];
        if (!src || src.name !== val.name) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "back-ref `#" + targetKey + "` → no prior response with clientId='" + val.resultOf +
            "' and name='" + val.name + "'");
        }
        var resolved = _pointerLookup(src.result, val.path, budget);
        if (resolved === undefined) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "back-ref `#" + targetKey + "` → path '" + val.path + "' resolved to undefined");
        }
        obj[targetKey] = resolved;
      } else {
        if (_movesThePrototype(key)) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidArguments",
            "argument '" + key + "' names a reserved property");
        }
        obj[key] = _resolveBackRefs(val, priorResponses, budget);
      }
    }
    return obj;
  }

  function _jsonBytes(value) {
    var encoded = JSON.stringify(value);
    return encoded === undefined ? 0 : Buffer.byteLength(encoded, "utf8");
  }

  function _expandedSize(node, memo) {
    if (node === null || typeof node !== "object") return _jsonBytes(node);
    var hit = memo.get(node);
    if (hit !== undefined) return hit;
    memo.set(node, 0);
    var total = 2;
    var i;
    if (Array.isArray(node)) {
      for (i = 0; i < node.length; i += 1) {
        total += _expandedSize(node[i], memo) + (i === 0 ? 0 : 1);
      }
    } else {
      var keys = Object.keys(node);
      var written = 0;
      for (i = 0; i < keys.length; i += 1) {
        var value = node[keys[i]];
        if (value === undefined || typeof value === "function") continue;
        total += _jsonBytes(keys[i]) + 1 + _expandedSize(value, memo) + (written === 0 ? 0 : 1);
        written += 1;
      }
    }
    memo.set(node, total);
    return total;
  }

  function _pointerLookup(node, path, budget) {
    if (typeof path !== "string") return undefined;
    if (path === "") return node;
    var parts = path.split("/");
    return _pointerFrom(node, parts, parts[0] === "" ? 1 : 0,
                        budget || { left: Infinity });
  }

  function _pointerFrom(node, parts, from, budget) {
    var cur = node;
    for (var i = from; i < parts.length; i += 1) {
      var seg = parts[i].replace(/~1/g, "/").replace(/~0/g, "~");                                     // allow:regex-no-length-cap — seg length bounded by path which is bounded by maxLineBytes upstream
      if (cur === null || typeof cur !== "object") return undefined;
      if (Array.isArray(cur)) {
        if (seg === "*") return _pointerOverEach(cur, parts, i + 1, budget);
        if (seg.length > MAX_ARRAY_INDEX_CHARS || !ARRAY_INDEX_RE.test(seg)) return undefined;
        var idx = Number(seg);
        if (idx >= cur.length) return undefined;
        cur = cur[idx];
      } else {
        if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
        cur = cur[seg];
      }
    }
    return cur;
  }

  function _pointerOverEach(items, parts, from, budget) {
    var out = [];
    function take(value) {
      var cost = _jsonBytes(value);
      budget.left -= cost > EXPANDED_ELEMENT_MIN_BYTES ? cost : EXPANDED_ELEMENT_MIN_BYTES;
      if (budget.left < 0) {
        throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
          "the `*` expansions in this call together pass what is left of maxSizeRequest; " +
          "every reference in one call draws on one budget, charged as each element is " +
          "taken, so no expansion is materialized and then measured");
      }
      out.push(value);
    }
    for (var i = 0; i < items.length; i += 1) {
      var value = _pointerFrom(items[i], parts, from, budget);
      if (value === undefined) return undefined;
      if (Array.isArray(value)) {
        for (var j = 0; j < value.length; j += 1) take(value[j]);
      } else {
        take(value);
      }
    }
    return out;
  }

  async function _permittedAccountIds(actor) {
    var info = await opts.accountsFor(actor);
    info = info || {};
    var accounts = info.accounts || {};
    var set = Object.create(null);
    if (accounts && typeof accounts === "object") {
      var ids = Object.keys(accounts);
      for (var i = 0; i < ids.length; i += 1) set[ids[i]] = true;
    }
    return set;
  }

  async function dispatch(actor, body) {
    if (!actor) {
      return _refusalResponse("urn:ietf:params:jmap:error:forbidden",
        "actor is required (operator must wire b.middleware.bearerAuth before this handler)");
    }
    var slotKey = _actorSlotKeyOrNull(actor, "dispatch");
    if (slotKey === null) {
      _emit("mail.server.jmap.unidentified_actor", { op: "dispatch" }, "denied");
      return _refusalResponse("urn:ietf:params:jmap:error:serverFail",
        "the authenticated actor carries none of the fields this listener reads to " +
        "tell one account's requests from another's (id, userId, username, sub, " +
        "principalId, email); name it with the actorKey option");
    }
    if (!requestSlots.take(slotKey)) {
      _emit("mail.server.jmap.request_refused",
        { type: "urn:ietf:params:jmap:error:limit", limit: "maxConcurrentRequests" }, "denied");
      return _refusalResponse("urn:ietf:params:jmap:error:limit",
        "maxConcurrentRequests (" + coreCapability.maxConcurrentRequests +
        ") requests are already in flight for this account",
        "maxConcurrentRequests", TOO_MANY_REQUESTS_STATUS);
    }
    var answer;
    try {
      answer = await _dispatchAdmitted(actor, body);
    } catch (e) {
      requestSlots.release(slotKey);
      throw e;
    }
    var stillRunning = answer && Array.isArray(answer.outstandingWork)
      ? answer.outstandingWork : [];
    if (stillRunning.length === 0) {
      requestSlots.release(slotKey);
    } else {
      _emit("mail.server.jmap.slot_held_for_outstanding_work",
        { count: stillRunning.length }, "warning");
      Promise.all(stillRunning).then(function () { requestSlots.release(slotKey); },
                                     function () { requestSlots.release(slotKey); });
    }
    if (answer && Object.prototype.hasOwnProperty.call(answer, "outstandingWork")) {
      delete answer.outstandingWork;
    }
    return answer;
  }

  async function _dispatchAdmitted(actor, body) {
    var parsed;
    try {
      parsed = guardJmap.validate(body, {
        profile: profile,
        posture: posture,
        serverCapabilities: serverCapabilities,
      });
    } catch (e) {
      var refusal = _refusalFromError(e);
      _emit("mail.server.jmap.request_refused",
        { type: refusal.type, limit: refusal.limit || null, reason: (e && e.message) || "" },
        "denied");
      return refusal;
    }

    var permittedAccounts;
    try {
      permittedAccounts = await _permittedAccountIds(actor);
    } catch (e) {
      _emit("mail.server.jmap.accounts_for_threw",
        { error: (e && e.message) || String(e) }, "failure");
      return _refusalResponse("urn:ietf:params:jmap:error:serverFail",
        "account authorization unavailable");
    }

    var methodResponses = [];
    var outstanding = [];
    var byClientId = Object.create(null);
    var expansionLeft = limits.maxSizeRequest;
    var expansionMemo = new WeakMap();
    for (var i = 0; i < parsed.methodCalls.length; i += 1) {
      var call = parsed.methodCalls[i];
      var methodName = call[0];
      var rawArgs    = call[1];
      var clientId   = call[2];
      var resolvedArgs;
      try {
        resolvedArgs = _resolveBackRefs(rawArgs, byClientId, { left: expansionLeft });
        var callCost = _expandedSize(resolvedArgs, expansionMemo);
        if (callCost > expansionLeft) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "the result references in this call expand to " + callCost + " bytes, which takes " +
            "this request past maxSizeRequest (" + limits.maxSizeRequest + " bytes) once " +
            "resolved; a reference names a value rather than copying it, so a chain of them " +
            "can describe far more than it sends");
        }
        expansionLeft -= callCost;
      } catch (e) {
        var refType = methodErrorName(e && e.code) || "invalidResultReference";
        methodResponses.push(["error", { type: refType, description: (e && e.message) || "" }, clientId]);
        continue;
      }
      if (!registry.has(methodName)) {
        methodResponses.push(["error",
          _methodError("unknownMethod",
            "Method '" + methodName + "' not implemented on this server"), clientId]);
        continue;
      }
      if (mailServerRegistry.jmapMethodTakesAccount(methodName)) {
        var named = resolvedArgs && typeof resolvedArgs === "object"
          ? resolvedArgs.accountId : undefined;
        if (typeof named !== "string" || named.length === 0) {
          _emit("mail.server.jmap.missing_account_id",
            { method: methodName, clientId: clientId }, "denied");
          methodResponses.push(["error",
            _methodError("invalidArguments", methodName.slice(-5) === "/copy"
              ? "'" + methodName + "' copies INTO the account named by accountId, " +
                "and reads FROM the one named by fromAccountId (RFC 8620 section 5.4); " +
                "there is no toAccountId argument"
              : "'" + methodName + "' requires accountId (RFC 8620 section 1.6.2)"),
            clientId]);
          continue;
        }
      }
      if (resolvedArgs && typeof resolvedArgs === "object" &&
          !mailServerRegistry.jmapMethodIsAccountFree(methodName)) {
        var argKeys = Object.keys(resolvedArgs);
        var deniedAccountId; var deniedHit = false;
        for (var aki = 0; aki < argKeys.length && !deniedHit; aki += 1) {
          if (!/[Aa]ccountId$/.test(argKeys[aki])) continue;
          var accVal = resolvedArgs[argKeys[aki]];
          if (accVal === undefined || accVal === null) continue;
          if (typeof accVal !== "string" || !permittedAccounts[accVal]) {
            deniedHit = true;
            deniedAccountId = typeof accVal === "string" ? accVal : null;
          }
        }
        if (deniedHit) {
          _emit("mail.server.jmap.account_not_found",
            { method: methodName, accountId: deniedAccountId, clientId: clientId }, "denied");
          methodResponses.push(["error",
            _methodError("accountNotFound",
              "accountId is not accessible to this actor"), clientId]);
          continue;
        }
      }
      if (resolvedArgs && typeof resolvedArgs === "object") {
        var over = null;
        if (NAMES_IDS_REQUESTED.test(methodName)) {
          if (_objectsNamed(resolvedArgs, _idArgumentsOf(resolvedArgs)) >
              limits.maxObjectsInGet) {
            over = "maxObjectsInGet " + limits.maxObjectsInGet;
          }
        } else if (NAMES_OBJECTS_WRITTEN.test(methodName)) {
          var setArgs = ["create", "update", "destroy", "emails"]
            .concat(_idArgumentsOf(resolvedArgs));
          if (_objectsNamed(resolvedArgs, setArgs) > limits.maxObjectsInSet) {
            over = "maxObjectsInSet " + limits.maxObjectsInSet;
          }
        }
        if (over !== null) {
          _emit("mail.server.jmap.objects_over_cap",
            { method: methodName, clientId: clientId, cap: over }, "denied");
          methodResponses.push(["error",
            _methodError("requestTooLarge",
              "'" + methodName + "' names more objects than " + over), clientId]);
          continue;
        }
      }
      if (!_legacyDeprecationEmitted && registry.source(methodName) === "builtin") {
        _legacyDeprecationEmitted = true;
        _emit("mail.server.jmap.methods_opt_deprecated",
          { note: "opts.methods is shimmed through b.mail.serverRegistry with auto-budget; " +
                  "future minor will require opts.overrides with explicit budgets" },
          "warning");
      }
      try {
        var result = await registry.dispatch(methodName, actor, resolvedArgs, {
          using:       parsed.using,
          createdIds:  parsed.createdIds,
          methodName:  methodName,
          clientId:    clientId,
        });
        var resultErrorName = methodName !== "Core/echo" && _resultIsMethodError(result)
          ? methodErrorName(result.type)
          : null;
        var listOver = /\/get$/.test(methodName) && result && typeof result === "object" &&
          Array.isArray(result.list) && result.list.length > limits.maxObjectsInGet;
        if (listOver) {
          _emit("mail.server.jmap.objects_over_cap",
            { method: methodName, clientId: clientId,
              cap: "maxObjectsInGet " + limits.maxObjectsInGet }, "denied");
          methodResponses.push(["error",
            _methodError("requestTooLarge",
              "'" + methodName + "' matches more objects than maxObjectsInGet " +
              limits.maxObjectsInGet), clientId]);
          byClientId[clientId] = { name: "error", result: { type: "requestTooLarge" } };
        } else if (resultErrorName !== null) {
          var asError = Object.assign({}, result, { type: resultErrorName });
          methodResponses.push(["error", asError, clientId]);
          byClientId[clientId] = { name: "error", result: asError };
        } else {
          methodResponses.push([methodName, result || {}, clientId]);
          byClientId[clientId] = { name: methodName, result: result || {} };
        }
      } catch (e) {
        var thrownType = e && typeof e.code === "string" ? methodErrorName(e.code) : null;
        if (e && e.outstandingWork && typeof e.outstandingWork.then === "function") {
          outstanding.push(e.outstandingWork);
        }
        _emit("mail.server.jmap.method_threw",
          { method: methodName, clientId: clientId, type: thrownType,
            error: (e && e.message) || String(e) }, "failure");
        methodResponses.push(["error",
          thrownType === null
            ? { type: "serverFail", description: "Method threw" }
            : { type: thrownType, description: (e && e.message) || "the method refused the call" },
          clientId]);
      }
    }

    _emit("mail.server.jmap.request",
      { methodCallCount: parsed.methodCalls.length, using: parsed.using });

    return {
      methodResponses: methodResponses,
      sessionState:    sessionState,
      createdIds:      parsed.createdIds,
      outstandingWork: outstanding,
    };
  }

  function _refusalResponse(type, description, limitName, statusOverride) {
    var problem = {
      type:        type,
      status:      statusOverride || REQUEST_PROBLEM_STATUS[type] || 400,
      detail:      description,
      description: description,
    };
    if (typeof limitName === "string" && limitName.length > 0) problem.limit = limitName;
    return problem;
  }

  function _refusalFromError(e) {
    var code = e && typeof e.code === "string" ? e.code : "";
    var type = Object.prototype.hasOwnProperty.call(REQUEST_PROBLEM_STATUS, code)
      ? code
      : "urn:ietf:params:jmap:error:serverFail";
    return _refusalResponse(type, (e && e.message) || "request refused",
      e && typeof e.limit === "string" ? e.limit : null);
  }

  function _refusalForUnreadableFrame(text) {
    try {
      guardJmap.validate(text, {
        profile: profile, posture: posture, serverCapabilities: serverCapabilities,
      });
    } catch (e) { return _refusalFromError(e); }
    return _refusalResponse("urn:ietf:params:jmap:error:notJSON",
      "WebSocket frame is not valid JSON");
  }

  function apiHandler(req, res) {
    var actor = req.user || (req.actor || null);
    var rawBody = req.body;
    if (rawBody === undefined) {
      res.statusCode = 400;
      res.setHeader("Content-Type", PROBLEM_JSON_TYPE);
      res.end(JSON.stringify(_refusalResponse("urn:ietf:params:jmap:error:notRequest",
        "request body missing (wire b.middleware.bodyParser before this handler)")));
      return;
    }
    dispatch(actor, rawBody).then(function (response) {
      if (response && response.type) {
        res.statusCode = typeof response.status === "number" && response.status > 0
          ? response.status
          : (REQUEST_PROBLEM_STATUS[response.type] || 400);
        res.setHeader("Content-Type", PROBLEM_JSON_TYPE);
      } else {
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
      }
      res.end(JSON.stringify(response));
    }, function (err) {
      _emit("mail.server.jmap.handler_threw",
        { error: (err && err.message) || String(err) }, "failure");
      res.statusCode = 500;
      res.setHeader("Content-Type", PROBLEM_JSON_TYPE);
      res.end(JSON.stringify(_refusalResponse("urn:ietf:params:jmap:error:serverFail",
        "Server error")));
    });
  }

  function _requireActor(req, res) {
    var actor = req.user || (req.actor || null);
    if (!actor) {
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:forbidden",
        description: "Authentication required",
      }));
      return null;
    }
    return actor;
  }

  function _forEachQueryParam(query, fn) {
    query.split("&").forEach(function (pair) {
      if (!pair) return;
      var eq = pair.indexOf("=");
      var k = eq === -1 ? pair : pair.slice(0, eq);
      var v = eq === -1 ? "" : pair.slice(eq + 1);
      fn(k, v);
    });
  }

  function sessionHandler(req, res) {
    var actor = _requireActor(req, res);
    if (!actor) return;
    Promise.resolve().then(function () { return opts.accountsFor(actor); })
      .then(function (accountInfo) {
        var info = accountInfo || { primaryAccounts: {}, accounts: {} };
        var defaultCaps = { "urn:ietf:params:jmap:core": coreCapability };
        var hasOperatorWsCap = Object.prototype.hasOwnProperty.call(
          serverCapabilities, "urn:ietf:params:jmap:websocket");
        if (webSocketEnabled && !hasOperatorWsCap) {
          defaultCaps["urn:ietf:params:jmap:websocket"] = {
            url:          opts.webSocketUrl || "/jmap/ws",
            supportsPush: true,
          };
        }
        var caps = Object.assign({}, defaultCaps, serverCapabilities);
        caps["urn:ietf:params:jmap:core"] = Object.assign({},
          serverCapabilities["urn:ietf:params:jmap:core"] || {}, coreCapability);
        if (!webSocketEnabled) delete caps["urn:ietf:params:jmap:websocket"];
        var session = {
          capabilities: caps,
          accounts:     info.accounts || {},
          primaryAccounts: info.primaryAccounts || {},
          username:     requestHelpers.actorDisplayName(actor, { actorKey: opts.actorKey }) ||
                        "unknown",
          apiUrl:       opts.apiUrl       || "/jmap/api",
          downloadUrl:  opts.downloadUrl  || "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
          uploadUrl:    opts.uploadUrl    || "/jmap/upload/{accountId}",
          eventSourceUrl: opts.eventSourceUrl || "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
          urlEndpointResolution: (webSocketEnabled && serverCapabilities["urn:ietf:params:jmap:websocket"])
            ? { useEndpoint: opts.webSocketUrl || "/jmap/ws", urlPrefix: "" }
            : undefined,
          webSocketUrl:   webSocketEnabled ? (opts.webSocketUrl || "/jmap/ws") : undefined,
          state:        sessionState,
        };
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(safeJson.stringify ? safeJson.stringify(session) : JSON.stringify(session));         // allow:bare-canonicalize-walk — JSON response, not signed payload
      })
      .catch(function (err) {
        _emit("mail.server.jmap.session_threw",
          { error: (err && err.message) || String(err) }, "failure");
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({
          type:        "urn:ietf:params:jmap:error:serverFail",
          description: "Session resource failed",
        }));
      });
  }

  function eventSourceHandler(req, res) {
    var actor = _requireActor(req, res);
    if (!actor) return;
    if (typeof opts.mailStore.subscribePush !== "function") {
      res.statusCode = 503;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:serverUnavailable",
        description: "Push subscribe backend not configured (mailStore.subscribePush)",
      }));
      return;
    }
    var url = String(req.url || "");
    var qIdx = url.indexOf("?");
    var query = qIdx === -1 ? "" : url.slice(qIdx + 1);
    var params = Object.create(null);
    _forEachQueryParam(query, function (k, v) {
      try { params[decodeURIComponent(k)] = decodeURIComponent(v); }
      catch (_e) { /* drop-silent — malformed % encoding */ }
    });
    var typesStr = params.types || "*";
    var types = typesStr === "*"
      ? null
      : structuredFields.splitUnquoted(typesStr, ",")
          .map(function (s) { return s.trim(); }).filter(Boolean);
    var closeAfter = (params.closeafter || "no").toLowerCase();
    if (closeAfter !== "no" && closeAfter !== "state") {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "closeafter must be 'no' or 'state' (RFC 8620 §7.3)",
      }));
      return;
    }
    var pingN;
    var pingDisabled = false;
    if (params.ping === "0") {
      pingDisabled = true;
      pingN = 0;
    } else {
      pingN = parseInt(params.ping, 10);
      if (!isFinite(pingN) || pingN < 5) pingN = 30;
      if (pingN > 900) pingN = 900;                                                                    // allow:raw-time-literal — explicit max-ping cap (15 minutes)
    }

    res.statusCode = 200;
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", cdnCacheControl.keepNoStore(res, "no-cache"));
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.write("retry: 5000\n\n");
    res.write(": connected\n\n");

    var closed = false;
    var pingTimer = null;
    var unsubscribe = null;

    function _send(eventName, data) {
      if (closed) return;
      try {
        res.write("event: " + eventName + "\n");
        res.write("data: " + (typeof data === "string" ? data : JSON.stringify(data)) + "\n\n");
      } catch (_e) {
        _cleanup();
      }
    }

    function _cleanup() {
      if (closed) return;
      closed = true;
      if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
      if (typeof unsubscribe === "function") {
        try { unsubscribe(); } catch (_e) { /* silent-catch: drop-silent — unsubscribe is best-effort cleanup */ }
      }
      try { res.end(); } catch (_e) { /* silent-catch: drop-silent — socket already torn down */ }
    }

    function _pingTick() {
      if (closed) return;
      var pingPayload = JSON.stringify({ interval: pingN });
      try { res.write("event: ping\ndata: " + pingPayload + "\n\n"); }
      catch (_e) { _cleanup(); }
    }

    var emitFn = function (event) {
      if (!event || closed) return;
      if (event.kind === "StateChange") {
        _send("state", {
          "@type":  "StateChange",
          changed:  event.changed || {},
          pushed:   event.pushed  || undefined,
        });
        if (closeAfter === "state") {
          _cleanup();
        }
      }
    };

    Promise.resolve()
      .then(function () { return opts.mailStore.subscribePush(actor, types, emitFn); })
      .then(function (unsub) {
        if (closed) {
          if (typeof unsub === "function") { try { unsub(); } catch (_e) { /* silent-catch: drop-silent — unsubscribe is best-effort cleanup */ } }
          return;
        }
        unsubscribe = typeof unsub === "function" ? unsub : null;
        if (!pingDisabled) {
          pingTimer = setInterval(_pingTick, pingN * 1000);                                            // allow:raw-time-literal — seconds → ms conversion
          if (pingTimer && typeof pingTimer.unref === "function") pingTimer.unref();
        }
      })
      .catch(function (err) {
        _emit("mail.server.jmap.push_subscribe_threw",
          { error: (err && err.message) || String(err) }, "failure");
        _cleanup();
      });

    req.on("close", _cleanup);
    req.on("error", _cleanup);
  }

  var DEFAULT_MAX_BLOB_BYTES = maxBlobBytes;
  var MAX_JMAP_ID_LEN = MAX_JMAP_ID_CHARS;
  var JMAP_ID_RE      = JMAP_ID_CHARS_RE;
  var MAX_URL_LEN     = 8192;

  function _splitPathSegments(rawUrl) {
    if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > MAX_URL_LEN) {
      return [];
    }
    var qIdx = rawUrl.indexOf("?");
    var pathOnly = qIdx === -1 ? rawUrl : rawUrl.slice(0, qIdx);
    var out = [];
    var cur = "";
    for (var i = 0; i < pathOnly.length; i += 1) {
      var ch = pathOnly.charCodeAt(i);
      if (ch === 0x2f) {
        if (cur.length > 0) { out.push(cur); cur = ""; }
      } else {
        cur += pathOnly[i];
      }
    }
    if (cur.length > 0) out.push(cur);
    return out;
  }

  function uploadHandler(req, res) {
    var actor = _requireActor(req, res);
    if (!actor) return;
    if (typeof opts.mailStore.uploadBlob !== "function") {
      res.statusCode = 503;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:serverUnavailable",
        description: "Upload backend not configured (mailStore.uploadBlob)",
      }));
      return;
    }
    var segments = _splitPathSegments(req.url);
    if (segments.length === 0) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Upload URL is empty or exceeds the " + MAX_URL_LEN + "-byte cap",
      }));
      return;
    }
    var accountId = (req.params && req.params.accountId) || segments[segments.length - 1] || "";
    if (!accountId || accountId.length > MAX_JMAP_ID_LEN || !JMAP_ID_RE.test(accountId)) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Upload URL missing or malformed accountId path segment (JMAP Id: [A-Za-z0-9_-]{1," + MAX_JMAP_ID_LEN + "})",
      }));
      return;
    }
    var uploadKey = _actorSlotKeyOrNull(actor, "upload");
    if (uploadKey === null) {
      _emit("mail.server.jmap.unidentified_actor", { op: "upload" }, "denied");
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:serverFail",
        description: "the authenticated actor carries no name this listener reads; " +
                     "name it with the actorKey option",
      }));
      try { req.destroy(); } catch (_e) { /* silent-catch: socket already torn down */ }
      return;
    }
    var contentType = req.headers && req.headers["content-type"]
      ? (_mediaTypeOf(String(req.headers["content-type"])) || "application/octet-stream")
      : "application/octet-stream";
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    DEFAULT_MAX_BLOB_BYTES,
      errorClass:  MailServerJmapError,
      sizeCode:    "mail-server-jmap/blob-too-large",
      sizeMessage: "Blob exceeds maxSizeUpload (" + DEFAULT_MAX_BLOB_BYTES + " bytes)",
    });
    if (!uploadSlots.take(uploadKey)) {
      _emit("mail.server.jmap.upload_refused",
        { accountId: accountId, limit: "maxConcurrentUpload" }, "denied");
      res.statusCode = TOO_MANY_REQUESTS_STATUS;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:limit",
        limit:       "maxConcurrentUpload",
        description: "maxConcurrentUpload (" + coreCapability.maxConcurrentUpload +
                     ") uploads are already in flight for this account",
      }));
      try { req.destroy(); } catch (_e) { /* silent-catch: socket already torn down */ }
      return;
    }
    var slotHeld = true;
    var bodyComplete = false;
    function _releaseUploadSlot() {
      if (!slotHeld) return;
      slotHeld = false;
      uploadSlots.release(uploadKey);
    }
    var refused = false;

    req.on("data", function (chunk) {
      if (refused) return;
      try { collector.push(chunk); }
      catch (_e) {
        refused = true;
        _releaseUploadSlot();
        res.statusCode = 413;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({
          type:        "urn:ietf:params:jmap:error:limit",
          limit:       "maxSizeUpload",
          description: "Blob exceeds maxSizeUpload (" + DEFAULT_MAX_BLOB_BYTES + " bytes)",
        }));
        try { req.destroy(); } catch (_e2) { /* silent-catch: socket already torn down */ }
      }
    });
    req.on("end", function () {
      if (refused) return;
      bodyComplete = true;
      var bytes = collector.result();
      Promise.resolve()
        .then(function () { return _permittedAccountIds(actor); })
        .then(function (permitted) {
          if (!permitted[accountId]) {
            _emit("mail.server.jmap.account_not_found",
              { op: "upload", accountId: accountId }, "denied");
            res.statusCode = 404;
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            res.end(JSON.stringify({
              type:        "urn:ietf:params:jmap:error:accountNotFound",
              description: "accountId is not accessible to this actor",
            }));
            return;
          }
          return _completeUpload(bytes);
        })
        .catch(function (err) {
          _emit("mail.server.jmap.upload_threw",
            { accountId: accountId, error: (err && err.message) || String(err) }, "failure");
          if (!res.headersSent) {
            res.statusCode = 500;
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            res.end(JSON.stringify({
              type:        "urn:ietf:params:jmap:error:serverFail",
              description: "Upload failed",
            }));
          }
        })
        .then(_releaseUploadSlot, _releaseUploadSlot);
    });

    function _completeUpload(bytes) {
      return Promise.resolve()
        .then(function () { return opts.mailStore.uploadBlob(actor, accountId, contentType, bytes); })
        .then(function (meta) {
          if (!meta || typeof meta !== "object" || typeof meta.blobId !== "string") {
            throw new MailServerJmapError("mail-server-jmap/bad-upload-result",
              "uploadBlob backend MUST return { blobId, type?, size? }");
          }
          res.statusCode = 201;
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.end(JSON.stringify({
            accountId: accountId,
            blobId:    meta.blobId,
            type:      meta.type || contentType,
            size:      typeof meta.size === "number" ? meta.size : bytes.length,
          }));
        });
    }
    req.on("error", function () {
      if (!refused) {
        refused = true;
        try { res.statusCode = 400; res.end(); }
        catch (_e) { /* silent-catch: socket already torn down */ }
      }
      _releaseUploadSlot();
    });
    req.on("close", function () { if (!bodyComplete) _releaseUploadSlot(); });
  }

  function downloadHandler(req, res) {
    var actor = _requireActor(req, res);
    if (!actor) return;
    if (typeof opts.mailStore.downloadBlob !== "function") {
      res.statusCode = 503;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:serverUnavailable",
        description: "Download backend not configured (mailStore.downloadBlob)",
      }));
      return;
    }
    var rawUrl = String(req.url || "");
    if (rawUrl.length > MAX_URL_LEN) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Download URL exceeds the " + MAX_URL_LEN + "-byte cap",
      }));
      return;
    }
    var acceptParam = null;
    var qAt = rawUrl.indexOf("?");
    if (qAt !== -1) {
      var qs = rawUrl.slice(qAt + 1);
      var parts = qs.split("&");
      for (var qi = 0; qi < parts.length; qi += 1) {
        if (parts[qi].indexOf("accept=") !== 0) continue;
        try { acceptParam = decodeURIComponent(parts[qi].slice("accept=".length)); }
        catch (_e) { acceptParam = null; }
        break;
      }
    }
    var pathSegs = _splitPathSegments(rawUrl);
    var routerSupplied = req.params && req.params.accountId && req.params.blobId && req.params.name;
    var accountId, blobId, fileName;
    if (routerSupplied) {
      accountId = req.params.accountId;
      blobId    = req.params.blobId;
      fileName  = req.params.name;
    } else if (pathSegs.length === 3) {
      accountId = pathSegs[0];
      blobId    = pathSegs[1];
      fileName  = _decodedPathSegment(pathSegs[2]);
    } else if (pathSegs.length >= 5 &&
               pathSegs[pathSegs.length - 5].toLowerCase() === "jmap" &&
               pathSegs[pathSegs.length - 4].toLowerCase() === "download") {
      accountId = pathSegs[pathSegs.length - 3];
      blobId    = pathSegs[pathSegs.length - 2];
      fileName  = _decodedPathSegment(pathSegs[pathSegs.length - 1]);
    } else {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Download URL must be /jmap/download/{accountId}/{blobId}/{name} (or router-stripped {accountId}/{blobId}/{name})",
      }));
      return;
    }
    if (!accountId || accountId.length > MAX_JMAP_ID_LEN || !JMAP_ID_RE.test(accountId)) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Download URL has malformed accountId segment (JMAP Id: [A-Za-z0-9_-]{1," + MAX_JMAP_ID_LEN + "})",
      }));
      return;
    }
    if (!blobId || blobId.length > MAX_JMAP_ID_LEN || !JMAP_ID_RE.test(blobId)) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "Download URL has malformed blobId segment (JMAP Id: [A-Za-z0-9_-]{1," + MAX_JMAP_ID_LEN + "})",
      }));
      return;
    }
    var downloadDenied = false;
    Promise.resolve()
      .then(function () { return _permittedAccountIds(actor); })
      .then(function (permitted) {
        if (!permitted[accountId]) {
          downloadDenied = true;
          _emit("mail.server.jmap.account_not_found",
            { op: "download", accountId: accountId, blobId: blobId }, "denied");
          res.statusCode = 404;
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.end(JSON.stringify({
            type:        "urn:ietf:params:jmap:error:accountNotFound",
            description: "accountId is not accessible to this actor",
          }));
          return undefined;
        }
        return opts.mailStore.downloadBlob(actor, accountId, blobId);
      })
      .then(function (result) {
        if (downloadDenied) return;
        if (!result || (typeof result !== "object" && !Buffer.isBuffer(result))) {
          res.statusCode = 404;
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.end(JSON.stringify({
            type:        "urn:ietf:params:jmap:error:invalidArguments",
            description: "Blob not found",
          }));
          return;
        }
        var bytes  = Buffer.isBuffer(result) ? result : result.bytes;
        function _usableType(candidate) {
          var s = String(candidate || "");
          return s.length > 0 && s.length <= MAX_MEDIA_TYPE_BYTES && MEDIA_TYPE_RE.test(s)   // allow:regex-no-length-cap — length-bounded on the line above
            ? s : null;
        }
        var bType = _usableType(result.type) || _usableType(acceptParam) ||
                    "application/octet-stream";
        if (!Buffer.isBuffer(bytes)) {
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.end(JSON.stringify({
            type:        "urn:ietf:params:jmap:error:serverFail",
            description: "downloadBlob backend returned a non-Buffer body",
          }));
          return;
        }
        res.statusCode = 200;
        res.setHeader("Content-Type", bType);
        res.setHeader("Content-Length", bytes.length);
        res.setHeader("Content-Disposition",
          staticServe.attachmentDisposition(String(fileName === undefined || fileName === null
            ? "" : fileName)));
        res.end(bytes);
      })
      .catch(function (err) {
        _emit("mail.server.jmap.download_threw",
          { accountId: accountId, blobId: blobId, error: (err && err.message) || String(err) }, "failure");
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify({
          type:        "urn:ietf:params:jmap:error:serverFail",
          description: "Download failed",
        }));
      });
  }

  function webSocketHandler(req, socket, head) {
    var actor = req.user || (req.actor || null);
    if (!actor) {
      try { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); }
      catch (_e) { /* silent-catch: socket already torn down */ }
      return null;
    }
    var conn = websocket.handleUpgrade(req, socket, head, {
      subprotocols:    ["jmap"],
      origins:         opts.webSocketOrigins || null,
      maxMessageBytes: webSocketMaxMessageBytes,
      permessageDeflate: opts.webSocketPermessageDeflate === true,
    });
    if (!conn) return null;
    if (conn.subprotocol !== "jmap") {
      try { conn.close(1002, "RFC 8887 requires Sec-WebSocket-Protocol: jmap"); }
      catch (_e) { /* silent-catch: closed */ }
      return null;
    }

    var pushUnsubscribe = null;
    var pushEnabled = false;
    var pushSetupPromise = null;
    var connClosed = false;

    function _sendJson(obj) {
      try { conn.send(JSON.stringify(obj)); }
      catch (_e) { /* silent-catch: socket already torn down */ }
    }

    function _sendRequestError(requestId, type, description, limitName, statusOverride) {
      var frame = {
        "@type":       "RequestError",
        requestId:     requestId || null,
        type:          type,
        status:        statusOverride || REQUEST_PROBLEM_STATUS[type] || 400,
        detail:        description,
        description:   description,
      };
      if (typeof limitName === "string" && limitName.length > 0) frame.limit = limitName;
      _sendJson(frame);
    }

    conn.on("message", function (data, isBinary) {
      if (isBinary) {
        _sendRequestError(null,
          "urn:ietf:params:jmap:error:notJSON",
          "WebSocket frame must be a JSON text frame (RFC 8887 §4)");
        return;
      }
      var text = data.toString("utf8");
      if (safeBuffer.byteLengthOf(data) > webSocketMaxMessageBytes) {
        _sendRequestError(null,
          "urn:ietf:params:jmap:error:limit",
          "WebSocket message exceeds maxSizeRequest", "maxSizeRequest");
        return;
      }
      var parsed;
      try {
        parsed = safeJson.parse(text, {
          maxBytes:   webSocketMaxMessageBytes,
          maxKeys:    guardJmap.MAX_KEYS_PER_OBJECT,
          allowProto: true, refuseProtoMover: true,
        });
      } catch (_e) {
        var unreadable = _refusalForUnreadableFrame(text);
        _sendRequestError(null, unreadable.type, unreadable.description,
          unreadable.limit || null, unreadable.status);
        return;
      }
      var type = parsed && parsed["@type"];
      var requestId = parsed && parsed.id;

      if (type === "Request") {
        Promise.resolve()
          .then(function () { return dispatch(actor, text); })
          .then(function (rv) {
            if (rv && typeof rv.type === "string" && typeof rv.description === "string") {
              _sendRequestError(requestId, rv.type, rv.description, rv.limit, rv.status);
              return;
            }
            _sendJson({
              "@type":         "Response",
              requestId:       requestId,
              methodResponses: rv.methodResponses,
              sessionState:    rv.sessionState,
              createdIds:      rv.createdIds,
            });
          })
          .catch(function (err) {
            _sendRequestError(requestId,
              (err && err.code) || "urn:ietf:params:jmap:error:serverFail",
              (err && err.message) || "Dispatch failed");
          });
        return;
      }

      if (type === "WebSocketPushEnable") {
        if (typeof opts.mailStore.subscribePush !== "function") {
          _sendRequestError(null,
            "urn:ietf:params:jmap:error:serverUnavailable",
            "Push subscribe backend not configured (mailStore.subscribePush)");
          return;
        }
        if (pushEnabled) return;
        pushEnabled = true;
        var dataTypes = Array.isArray(parsed.dataTypes) && parsed.dataTypes.length > 0
          ? parsed.dataTypes : null;
        pushSetupPromise = Promise.resolve()
          .then(function () {
            return opts.mailStore.subscribePush(actor, dataTypes, function (event) {
              if (!event || connClosed) return;
              if (event.kind === "StateChange") {
                _sendJson({
                  "@type":  "StateChange",
                  changed:  event.changed || {},
                  pushed:   event.pushed,
                });
              }
            });
          })
          .then(function (unsub) {
            pushUnsubscribe = typeof unsub === "function" ? unsub : null;
            if ((connClosed || !pushEnabled) && typeof pushUnsubscribe === "function") {
              try { pushUnsubscribe(); }
              catch (_e) { /* silent-catch: drop-silent — unsubscribe is best-effort */ }
              pushUnsubscribe = null;
            }
          })
          .catch(function (err) {
            pushEnabled = false;
            _sendRequestError(null,
              "urn:ietf:params:jmap:error:serverFail",
              (err && err.message) || "subscribePush threw");
          });
        return;
      }

      if (type === "WebSocketPushDisable") {
        pushEnabled = false;
        if (typeof pushUnsubscribe === "function") {
          try { pushUnsubscribe(); }
          catch (_e) { /* silent-catch: drop-silent — unsubscribe is best-effort */ }
        }
        pushUnsubscribe = null;
        return;
      }

      _sendRequestError(requestId,
        "urn:ietf:params:jmap:error:unknownDataType",
        "Unknown WebSocket frame @type '" + type + "' (RFC 8887 §4)");
    });

    conn.on("close", function () {
      connClosed = true;
      pushEnabled = false;
      if (typeof pushUnsubscribe === "function") {
        try { pushUnsubscribe(); }
        catch (_e) { /* silent-catch: drop-silent */ }
      }
      pushUnsubscribe = null;
    });
    void pushSetupPromise;

    return conn;
  }

  function discoveryHandler(req, res) {
    res.statusCode = 302;
    res.setHeader("Location", opts.sessionUrl || "/jmap/session");
    res.end();
  }

  return {
    create:               create,
    dispatch:             dispatch,
    apiHandler:           apiHandler,
    sessionHandler:       sessionHandler,
    discoveryHandler:     discoveryHandler,
    eventSourceHandler:   eventSourceHandler,
    uploadHandler:        uploadHandler,
    downloadHandler:      downloadHandler,
    webSocketHandler:     webSocketHandler,
    MailServerJmapError:  MailServerJmapError,
  };
}

/**
 * @primitive b.mail.server.jmap.emailSubmissionSetHandler
 * @signature b.mail.server.jmap.emailSubmissionSetHandler(opts)
 * @since     0.11.38
 * @status    stable
 * @related   b.mail.server.jmap.create
 * @compliance gdpr, soc2
 *
 * Reference implementation of JMAP `EmailSubmission/set` (RFC 8621 §7.5)
 * that composes `b.mail.send.deliver`. Returns an async method-handler
 * suitable for plumbing into `b.mail.server.jmap.create({ methods: ... })`.
 *
 * The handler:
 *
 *   1. Walks `args.create` per RFC 8621 §7.5. For each EmailSubmission:
 *      - Refuses `identityId` not registered in `opts.identities(accountId)`.
 *      - Refuses `emailId` absent — calls `opts.lookupEmail(emailId,
 *        accountId, actor)` to fetch the RFC 822 blob (refuses
 *        `emailNotFound` when null).
 *      - Refuses missing or oversize `envelope.rcptTo` (max 1000 per
 *        the same recipient cap `b.mail.send.deliver` enforces).
 *      - Validates `envelope.mailFrom.email` matches the identity's
 *        authorized addresses (`forbiddenMailFrom` per RFC 8621
 *        §7.5.1.2 when not).
 *   2. Hands the RFC 822 blob to the supplied `opts.deliver(envelope)`
 *      (a `b.mail.send.deliver.create()` instance).
 *   3. Maps `deliver`'s `{ delivered, deferred, failed }` result into
 *      JMAP `deliveryStatus` (`recipient → { smtpReply, delivered,
 *      displayed }` per RFC 8621 §7.4).
 *   4. Calls `opts.onCreated(subId, submission, accountId)` so the
 *      operator can persist the EmailSubmission record (state survives
 *      across JMAP requests via `EmailSubmission/get`).
 *
 * `args.destroy` removes EmailSubmission records via
 * `opts.onDestroyed(subId, accountId)` — the delivery itself cannot
 * be unsent at this point; `destroy` only removes the JMAP-visible
 * record.
 *
 * `args.update` is honored only for the `undoStatus: "canceled"`
 * transition per RFC 8621 §7.5.2 (operators with a queue-based
 * deferred-send model wire `opts.onCancel(subId, accountId)`; the
 * reference handler refuses with `cannotUnsend` when no `onCancel`
 * is configured).
 *
 * @opts
 *   deliver:        async function (envelope),    // b.mail.send.deliver instance (REQUIRED)
 *   lookupEmail:    async function (emailId, accountId, actor) → Buffer|null,  (REQUIRED)
 *   identities:     function (accountId) → [ { id, email, mayDelegate } ], (REQUIRED)
 *   onCreated:      async function (subId, submission, accountId), (optional)
 *   onDestroyed:    async function (subId, accountId),             (optional)
 *   onCancel:       async function (subId, accountId) → boolean,   (optional — undo support)
 *   maxRecipients:  number,                                       // default 1000
 *
 * @example
 *   var deliver = b.mail.send.deliver({ hostname: "mta.example.com" });
 *   var emailSubSet = b.mail.server.jmap.emailSubmissionSetHandler({
 *     deliver:     deliver,
 *     lookupEmail: async function (emailId, accountId) {
 *       return mailStore.fetchBlob(accountId, emailId);
 *     },
 *     identities:  function (accountId) {
 *       return [{ id: "I1", email: "ops@example.com" }];
 *     },
 *     onCreated:   async function (id, sub, accountId) { return; },
 *   });
 *
 *   var jmap = b.mail.server.jmap.create({
 *     mailStore:   store,
 *     accountsFor: async function () { return { primaryAccounts: {}, accounts: {} }; },
 *     methods:     { "EmailSubmission/set": emailSubSet },
 *   });
 */
function _fromHeaderAddress(rfc822) {
  var text;
  if (Buffer.isBuffer(rfc822)) {
    var end = rfc822.indexOf("\r\n\r\n");
    if (end === -1) end = rfc822.indexOf("\n\n");
    text = (end === -1 ? rfc822 : rfc822.subarray(0, end)).toString("utf8");
  } else if (typeof rfc822 === "string") {
    var at = rfc822.indexOf("\r\n\r\n");
    if (at === -1) at = rfc822.indexOf("\n\n");
    text = at === -1 ? rfc822 : rfc822.slice(0, at);
  } else return null;
  var lines = text.split(/\r?\n/);
  var values = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (safeBuffer.byteLengthOf(line) > safeMime.DEFAULTS.maxHeaderLineBytes) return null;
    if (line === "") break;
    var isContinuation = line.charAt(0) === " " || line.charAt(0) === "\t";
    if (isContinuation) {
      if (current !== null) current.value += " " + line.trim();
      continue;
    }
    current = null;
    var colon = line.indexOf(":");
    if (colon === -1 || !safeMime.isHeaderFieldName(line.slice(0, colon))) continue;
    var field = structuredFields.parseKeyValuePiece(line, ":");
    if (field.value === null || field.key !== "from") continue;
    current = { value: field.value.trim() };
    values.push(current);
  }
  if (values.length === 0) return null;
  var all = [];
  for (var v = 0; v < values.length; v += 1) {
    var one = _mailboxAddresses(values[v].value);
    for (var k = 0; k < one.length; k += 1) all.push(one[k]);
  }
  return all;
}

function _afterQuotedPair(value, i) {
  return i + 2 > value.length ? value.length : i + 2;
}

function _carriesAnAuthor(segment) {
  var i = _skipCfws(segment, 0);
  if (i === -1) return true;
  return i !== segment.length;
}

function _closingSemicolon(value, i) {
  while (i < value.length) {
    var c = value.charAt(i);
    if (c === "\\") { i = _afterQuotedPair(value, i); continue; }
    if (c === "(") { i = _skipComment(value, i); if (i === -1) return -1; continue; }
    if (c === '"') {
      i += 1;
      while (i < value.length) {
        var q = value.charAt(i);
        if (q === "\\") { i = _afterQuotedPair(value, i); continue; }
        i += 1;
        if (q === '"') break;
      }
      continue;
    }
    if (c === ";") return i;
    i += 1;
  }
  return -1;
}

function _mailboxAddresses(value, groupDepth) {
  var out = [];
  var start = 0;
  var i = 0;
  var angles = 0;
  var brackets = 0;
  while (i <= value.length) {
    if (i === value.length || _isTopLevelComma(value, i)) {
      var segment = value.slice(start, i);
      var one = _firstMailboxAddress(segment);
      if (one === null) {
        if (_carriesAnAuthor(segment)) out.push(null);
      } else {
        out.push(one);
      }
      start = i + 1;
      i += 1;
      continue;
    }
    var ch = value.charAt(i);
    if (ch === "\\") { i = _afterQuotedPair(value, i); continue; }
    if (ch === "(") {
      var depth = 0;
      while (i < value.length) {
        var c = value.charAt(i);
        if (c === "\\") { i = _afterQuotedPair(value, i); continue; }
        if (c === "(") depth += 1;
        else if (c === ")") { depth -= 1; if (depth === 0) { i += 1; break; } }
        i += 1;
      }
      continue;
    }
    if (ch === '"') {
      i += 1;
      while (i < value.length) {
        var q = value.charAt(i);
        if (q === "\\") { i = _afterQuotedPair(value, i); continue; }
        i += 1;
        if (q === '"') break;
      }
      continue;
    }
    if (ch === "<") { angles += 1; i += 1; continue; }
    if (ch === ">") { if (angles > 0) angles -= 1; i += 1; continue; }
    if (ch === "[") { brackets += 1; i += 1; continue; }
    if (ch === "]") { if (brackets > 0) brackets -= 1; i += 1; continue; }
    if (ch === ":" && angles === 0 && brackets === 0) {
      var displayName = value.slice(start, i);
      var pastCfws = _skipCfws(displayName, 0);
      if (pastCfws === -1 || pastCfws === displayName.length ||
          !_phraseIsReadable(displayName)) {
        out.push(null);
        return out;
      }
      var nesting = groupDepth === undefined ? 0 : groupDepth;
      var end = nesting >= MAX_GROUP_NESTING ? -1 : _closingSemicolon(value, i + 1);
      if (end === -1) { out.push(null); return out; }
      var members = _mailboxAddresses(value.slice(i + 1, end), nesting + 1);
      if (members.length === 0) out.push(null);
      for (var m = 0; m < members.length; m += 1) out.push(members[m]);
      i = end + 1;
      start = i;
      continue;
    }
    i += 1;
  }
  return out;
}

function _isTopLevelComma(value, i) {
  return value.charAt(i) === ",";
}

function _addrSpecOf(text) {
  var out = "";
  var i = 0;
  while (i < text.length) {
    var ch = text.charAt(i);
    if (ch === "\\") { out += text.slice(i, i + 2); i += 2; continue; }
    if (ch === "\"") {
      var quoted = ch;
      i += 1;
      while (i < text.length) {
        var q = text.charAt(i);
        if (q === "\\") { quoted += text.slice(i, i + 2); i += 2; continue; }
        quoted += q;
        i += 1;
        if (q === "\"") break;
      }
      out += quoted;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "(") {
      var after = _skipCfws(text, i);
      if (after === -1) return "";
      if (out.length > 0 && after < text.length &&
          !_isAtomBoundary(out.charAt(out.length - 1)) &&
          !_isAtomBoundary(text.charAt(after))) {
        return "";
      }
      i = after;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function _skipComment(value, i) {
  var depth = 0;
  while (i < value.length) {
    var c = value.charAt(i);
    if (c === "\\") { i = _afterQuotedPair(value, i); continue; }
    if (c === "(") depth += 1;
    else if (c === ")") { depth -= 1; if (depth === 0) return i + 1; }
    i += 1;
  }
  return -1;
}

function _skipCfws(value, i) {
  while (i < value.length) {
    var c = value.charAt(i);
    if (c === " " || c === "\t") { i += 1; continue; }
    if (c !== "(") return i;
    i = _skipComment(value, i);
    if (i === -1) return -1;
  }
  return i;
}

function _closingAngle(value, i) {
  while (i < value.length) {
    var c = value.charAt(i);
    if (c === "\\") { i = _afterQuotedPair(value, i); continue; }
    if (c === "(") { i = _skipComment(value, i); if (i === -1) return -1; continue; }
    if (c === '"') {
      i += 1;
      while (i < value.length) {
        var q = value.charAt(i);
        if (q === "\\") { i = _afterQuotedPair(value, i); continue; }
        i += 1;
        if (q === '"') break;
      }
      continue;
    }
    if (c === ">") return i;
    i += 1;
  }
  return -1;
}

function _phraseIsReadable(text) {
  var i = 0;
  while (i < text.length) {
    var c = text.charAt(i);
    if (c === " " || c === "\t") { i += 1; continue; }
    if (c === "(") { i = _skipComment(text, i); if (i === -1) return false; continue; }
    if (c === '"') {
      i += 1;
      var closed = false;
      while (i < text.length) {
        var q = text.charAt(i);
        if (q === "\\") { i = _afterQuotedPair(text, i); continue; }
        i += 1;
        if (q === '"') { closed = true; break; }
      }
      if (!closed) return false;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(ATEXT_EXCLUDED, c)) return false;
    i += 1;
  }
  return true;
}

function _firstMailboxAddress(value) {
  var open = -1;
  var i = 0;
  while (i < value.length) {
    var ch = value.charAt(i);
    if (ch === "\\") { i = _afterQuotedPair(value, i); continue; }
    if (ch === "(") { i = _skipComment(value, i); if (i === -1) return null; continue; }
    if (ch === '"') {
      i += 1;
      var quoteClosed = false;
      while (i < value.length) {
        var q = value.charAt(i);
        if (q === "\\") { i = _afterQuotedPair(value, i); continue; }
        i += 1;
        if (q === '"') { quoteClosed = true; break; }
      }
      if (!quoteClosed) return null;
      continue;
    }
    if (ch === "<") { open = i; break; }
    i += 1;
  }

  if (open === -1) {
    if (_skipCfws(value, 0) === -1) return null;
    var bare = _addrSpecOf(value);
    return bare.length === 0 ? null : bare;
  }

  if (!_phraseIsReadable(value.slice(0, open))) return null;
  var close = _closingAngle(value, open + 1);
  if (close === -1) return null;
  var after = _skipCfws(value, close + 1);
  if (after === -1 || after !== value.length) return null;
  var inner = _addrSpecOf(value.slice(open + 1, close));
  return inner.length === 0 ? null : inner;
}

function _headerParam(headerValue, name) {
  if (typeof headerValue !== "string" || headerValue === "") return null;
  var pairs = structuredFields.parseTagList(headerValue);
  for (var i = 0; i < pairs.length; i += 1) {
    if (pairs[i][0] !== name) continue;
    var value = structuredFields.stripDoubleQuotes(String(pairs[i][1]).trim());
    return value.length === 0 ? null : value;
  }
  return null;
}

function _dispositionOf(headerValue) {
  return _mediaTypeOf(headerValue);
}

function _mediaTypeOf(headerValue) {
  if (typeof headerValue !== "string" || headerValue === "") return null;
  var semi = headerValue.indexOf(";");
  var token = (semi === -1 ? headerValue : headerValue.slice(0, semi)).trim().toLowerCase();
  return token.length === 0 ? null : token;
}

function _firstOverlongBlobId(node) {
  if (typeof node.blobId === "string" && node.blobId.length > MAX_JMAP_ID_CHARS) {
    return node.blobId;
  }
  var subs = node.subParts || [];
  for (var i = 0; i < subs.length; i += 1) {
    var found = _firstOverlongBlobId(subs[i]);
    if (found !== null) return found;
  }
  return null;
}

function _comparePaths(left, right) {
  var n = Math.min(left.length, right.length);
  for (var i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function _bodyEntriesFor(selection, want) {
  var out = [];
  var other = want === "text" ? selection.html : selection.text;
  var own = want === "text" ? selection.text : selection.html;
  for (var i = 0; i < own.length; i += 1) out.push(own[i]);
  for (var j = 0; j < other.length; j += 1) {
    if (!other[j].representation) out.push(other[j]);
  }
  out.sort(function (a, c) { return _comparePaths(a.path, c.path); });
  return out;
}

function _charsetOf(part, headers) {
  var params = part.leaf && part.leaf.contentTypeParams;
  if (params && typeof params === "object") {
    return typeof params.charset === "string" ? params.charset : null;
  }
  return _headerParam(headers.get("content-type"), "charset");
}

var MAX_LANGUAGE_TAG_CHARS = 64;
var LANGUAGE_TAG_RE = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/;

function _languageTagsOf(headers) {
  var raw = headers.get("content-language");
  if (typeof raw !== "string") return null;
  var pieces = structuredFields.splitTopLevel(raw, ",");
  var out = [];
  for (var i = 0; i < pieces.length; i += 1) {
    var tag = pieces[i].trim();
    if (tag.length === 0 || tag.length > MAX_LANGUAGE_TAG_CHARS) continue;
    if (!LANGUAGE_TAG_RE.test(tag)) continue;
    out.push(tag);
  }
  return out.length > 0 ? out : null;
}

function _treeHasNoBodies(part) {
  if (part.parts && part.parts.length > 0) {
    for (var i = 0; i < part.parts.length; i += 1) {
      if (_treeHasNoBodies(part.parts[i])) return true;
    }
    return false;
  }
  return !!(part.leaf && (part.leaf.body === null || part.leaf.body === undefined));
}

function _blobIdFor(prefix, path) {
  var head = String(prefix.length) + "-" + prefix;
  return path.length === 0 ? head : head + "-" + path.join("-");
}

function _bodyPartFrom(part, path, prefix) {
  var headers = part.headers;
  var contentType = (part.leaf && part.leaf.contentType) ||
    _dispositionOf(headers.get("content-type")) || "text/plain";
  var subParts = null;
  if (part.parts && part.parts.length > 0) {
    subParts = [];
    for (var i = 0; i < part.parts.length; i += 1) {
      subParts.push(_bodyPartFrom(part.parts[i], path.concat([i]), prefix));
    }
  }
  var isLeaf = subParts === null && contentType.slice(0, 10) !== "multipart/";
  var partId = path.length === 0 ? "1" : path.map(function (n) { return n + 1; }).join(".");
  var cid = headers.get("content-id");
  if (typeof cid === "string") cid = cid.replace(/^\s*<|>\s*$/g, "").trim() || null;
  return {
    partId:      isLeaf ? partId : null,
    blobId:      isLeaf ? _blobIdFor(prefix, path) : null,
    size:        part.leaf && part.leaf.body ? safeBuffer.byteLengthOf(part.leaf.body) : 0,
    name:        safeMime.filenameFromHeaders(headers),
    type:        contentType,
    charset:     _charsetOf(part, headers),
    disposition: _dispositionOf(headers.get("content-disposition")),
    cid:         typeof cid === "string" ? cid : null,
    language:    _languageTagsOf(headers),
    location:    headers.get("content-location") || null,
    subParts:    isLeaf ? null : (subParts === null ? [] : subParts),
  };
}

/**
 * @primitive b.mail.server.jmap.emailBodyProperties
 * @signature b.mail.server.jmap.emailBodyProperties(tree, opts)
 * @since     0.20.32
 * @status    stable
 * @related   b.mail.server.jmap.create, b.safeMime.parse, b.safeMime.extractAttachments
 *
 * Build the body-part properties RFC 8621 section 4.1.4 defines for an
 * `Email`, from the tree `b.safeMime.parse` returns. Answers
 * `{ bodyStructure, textBody, htmlBody, attachments, hasAttachment }`, where
 * every `EmailBodyPart` carries the `partId` and `blobId` a client needs to
 * fetch one part through the download endpoint.
 *
 * `Email/get` is an operator-supplied handler, so this is the piece the
 * handler composes. Without these properties a client cannot see that a
 * message carries a file: the response is well formed, the client reads the
 * properties it knows, and a message with three attachments looks the same
 * as one with none.
 *
 * `blobId` is `<prefix length>-<blobIdPrefix>-<part path>`, and the prefix
 * must satisfy the JMAP Id grammar of RFC 8620 section 1.2, because the
 * download handler refuses anything else. That grammar admits `-` and `_`,
 * so a separator also occurs inside a prefix: the length in front lets a
 * reader take exactly the prefix and leave the path, and two messages whose
 * ids differ never name one blob. A multipart carries no `blobId` of its own.
 *
 * Throws `mail-server-jmap/bad-opts` for an `opts` that is not an object,
 * `mail-server-jmap/bad-blob-id-prefix` for a `blobIdPrefix` that is not a JMAP
 * Id and `mail-server-jmap/blob-id-too-long` for one that leaves no room for a
 * part's own path within the id length, and
 * `mail-server-jmap/bad-mime-tree` for a `tree` that is not one
 * `b.safeMime.parse` produced. A tree parsed in structure-only mode carries no
 * part bodies, so reading one raises `safe-mime/structure-only`.
 *
 * @opts
 *   blobIdPrefix: string,   // required — the message's own id, scoping each part's blobId
 *
 * @example
 *   var tree = b.safeMime.parse(rawMessageBytes);
 *   var body = b.mail.server.jmap.emailBodyProperties(tree, { blobIdPrefix: message.objectid });
 *   body.hasAttachment;            // → true
 *   body.attachments[0].name;      // → "report.pdf"
 *   body.attachments[0].blobId;    // → "8-obj_1f3c-1"
 */
function _refusePositiveIntegerOpt(value, name) {
  if (value === undefined || value === null) return;
  if (typeof value !== "number" || !isFinite(value) || value < 1 || Math.floor(value) !== value) {
    throw new MailServerJmapError("mail-server-jmap/bad-concurrency",
      "mail.server.jmap.create: opts." + name + " must be a positive integer; it is " +
      "the number of " + (name === "maxConcurrentUpload" ? "uploads" : "requests") +
      " an account may have in flight, and the session advertises it to every client");
  }
}

function _refuseBlobCap(value) {
  if (value === undefined || value === null) return;
  if (typeof value !== "number" || !isFinite(value) || value < 1 || Math.floor(value) !== value) {
    throw new MailServerJmapError("mail-server-jmap/bad-blob-cap",
      "mail.server.jmap.create: opts.maxBlobBytes must be a positive integer; it is " +
      "the largest upload this listener accepts, the session advertises it as " +
      "maxSizeUpload, and the upload reader refuses a cap it cannot apply after " +
      "the request has already taken one of the account's upload slots");
  }
}

function _isCollationName(s) {
  for (var i = 0; i < s.length; i += 1) {
    var cc = s.charCodeAt(i);
    if (cc <= 0x20 || cc === 0x7F) return false;
  }
  return true;
}

function _refuseCollations(value) {
  if (value === undefined || value === null) return;
  validateOpts.optionalNonEmptyStringArray(value,
    "mail.server.jmap.create: opts.collationAlgorithms (the RFC 4790 collations the " +
    "session advertises, which RFC 8620 §2 defines as an array of names)",
    MailServerJmapError, "mail-server-jmap/bad-collations");
  if (value.length === 0) {
    throw new MailServerJmapError("mail-server-jmap/bad-collations",
      "mail.server.jmap.create: opts.collationAlgorithms is empty; a session that " +
      "advertises no collation tells every client it cannot sort, which is not what " +
      "omitting the option means. Omit it to keep the default set");
  }
  for (var i = 0; i < value.length; i += 1) {
    if (!_isCollationName(value[i])) {
      throw new MailServerJmapError("mail-server-jmap/bad-collations",
        "mail.server.jmap.create: opts.collationAlgorithms names " +
        JSON.stringify(value[i]) + ", which is not a collation name: RFC 4790 §3.1 names " +
        "carry no whitespace or control characters, and this one goes into the session " +
        "capability a client parses. Which collations exist is the operator's answer, since " +
        "the handlers registered here do the sorting");
    }
  }
}

function _concurrencySlots(max) {
  var inUse = Object.create(null);
  return {
    take: function (key) {
      var held = inUse[key] || 0;
      if (held >= max) return false;
      inUse[key] = held + 1;
      return true;
    },
    release: function (key) {
      var held = inUse[key] || 0;
      if (held <= 1) delete inUse[key];
      else inUse[key] = held - 1;
    },
  };
}


function emailBodyProperties(tree, opts) {
  validateOpts.requireObject(opts, "mail.server.jmap.emailBodyProperties",
    MailServerJmapError, "mail-server-jmap/bad-opts");
  if (!tree || typeof tree !== "object" || !tree.headers) {
    throw new MailServerJmapError("mail-server-jmap/bad-mime-tree",
      "mail.server.jmap.emailBodyProperties: tree must be the object b.safeMime.parse returns");
  }
  if (_treeHasNoBodies(tree)) {
    throw new MailServerJmapError("safe-mime/structure-only",
      "mail.server.jmap.emailBodyProperties: this tree was parsed with structureOnly, " +
      "which keeps no bodies, so a part's size cannot be reported");
  }
  var prefix = opts.blobIdPrefix;
  if (typeof prefix !== "string" || prefix.length === 0 ||
      prefix.length > MAX_JMAP_ID_CHARS || !JMAP_ID_CHARS_RE.test(prefix)) {
    throw new MailServerJmapError("mail-server-jmap/bad-blob-id-prefix",
      "mail.server.jmap.emailBodyProperties: opts.blobIdPrefix must be a JMAP Id " +
      "(RFC 8620 section 1.2: [A-Za-z0-9_-]{1," + MAX_JMAP_ID_CHARS + "}), because it " +
      "scopes each part's blobId and the download handler refuses anything else");
  }

  var bodyStructure = _bodyPartFrom(tree, [], prefix);
  var overLong = _firstOverlongBlobId(bodyStructure);
  if (overLong !== null) {
    throw new MailServerJmapError("mail-server-jmap/blob-id-too-long",
      "mail.server.jmap.emailBodyProperties: opts.blobIdPrefix leaves no room for a " +
      "part path: '" + overLong.slice(0, 40) + "...' is " + overLong.length +
      " characters, over the " + MAX_JMAP_ID_CHARS + " a JMAP Id allows, so the " +
      "download handler would refuse the blob this advertises");
  }
  var nodesByPath = Object.create(null);
  (function index(node, path) {
    nodesByPath[path.join(".")] = node;
    for (var i = 0; i < (node.subParts || []).length; i += 1) {
      index(node.subParts[i], path.concat([i]));
    }
  })(bodyStructure, []);
  function _nodesFor(entries) {
    var out = [];
    for (var i = 0; i < entries.length; i += 1) {
      var node = nodesByPath[entries[i].path.join(".")];
      if (node) out.push(node);
    }
    return out;
  }
  var selection = safeMime.selectBodyParts(tree);
  var textBody = _nodesFor(_bodyEntriesFor(selection, "text"));
  var htmlBody = _nodesFor(_bodyEntriesFor(selection, "html"));
  var attachments = _nodesFor(selection.files);

  return {
    bodyStructure: bodyStructure,
    textBody:      textBody,
    htmlBody:      htmlBody,
    attachments:   attachments,
    hasAttachment: attachments.length > 0,
  };
}

function emailSubmissionSetHandler(opts) {
  validateOpts.requireObject(opts, "mail.server.jmap.emailSubmissionSetHandler",
    MailServerJmapError, "mail-server-jmap/bad-opts");
  if (typeof opts.deliver !== "function") {
    throw new MailServerJmapError("mail-server-jmap/no-deliver",
      "emailSubmissionSetHandler: opts.deliver async function is required " +
      "(compose b.mail.send.deliver.create({ ... }))");
  }
  if (typeof opts.lookupEmail !== "function") {
    throw new MailServerJmapError("mail-server-jmap/no-lookup-email",
      "emailSubmissionSetHandler: opts.lookupEmail(emailId, accountId, actor) async function is required");
  }
  if (typeof opts.identities !== "function") {
    throw new MailServerJmapError("mail-server-jmap/no-identities",
      "emailSubmissionSetHandler: opts.identities(accountId) function is required (returns Array<{id,email}>)");
  }
  var maxRecipients = opts.maxRecipients || 1000;
  if (typeof maxRecipients !== "number" || !isFinite(maxRecipients) || maxRecipients < 1) {
    throw new MailServerJmapError("mail-server-jmap/bad-max-recipients",
      "emailSubmissionSetHandler: opts.maxRecipients MUST be a positive integer");
  }
  var identityMatchOpts = { subaddressDelimiter: opts.subaddressDelimiter };

  return async function emailSubmissionSet(actor, args, _ctx) {
    if (!args || typeof args !== "object" || typeof args.accountId !== "string") {
      throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "EmailSubmission/set: accountId is required");
    }
    var accountId = args.accountId;
    var created     = Object.create(null);
    var notCreated  = Object.create(null);
    var updated     = Object.create(null);
    var notUpdated  = Object.create(null);
    var destroyed   = [];
    var notDestroyed = Object.create(null);

    if (args.create && typeof args.create === "object" && !Array.isArray(args.create)) {
      var createKeys = Object.keys(args.create);
      for (var ci = 0; ci < createKeys.length; ci += 1) {
        var clientId = createKeys[ci];
        var sub = args.create[clientId];
        try {
          var result = await _processCreate(actor, accountId, sub);
          created[clientId] = result;
          if (typeof opts.onCreated === "function") {
            try { await opts.onCreated(result.id, result, accountId); }
            catch (_e) { /* drop-silent — persistence is operator side-effect */ }
          }
        } catch (err) {
          notCreated[clientId] = _jmapErrorShape(err);
        }
      }
    }

    if (args.update && typeof args.update === "object" && !Array.isArray(args.update)) {
      var updateKeys = Object.keys(args.update);
      for (var ui = 0; ui < updateKeys.length; ui += 1) {
        var subId = updateKeys[ui];
        var patch = args.update[subId];
        if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
          notUpdated[subId] = { type: "invalidPatch", description: "patch must be an object" };
          continue;
        }
        var patchKeys = Object.keys(patch);
        var nonUndo = patchKeys.filter(function (k) { return k !== "undoStatus"; });
        if (nonUndo.length > 0) {
          notUpdated[subId] = {
            type:        "invalidProperties",
            properties:  nonUndo,
            description: "only undoStatus may be updated on an EmailSubmission",
          };
          continue;
        }
        if (patch.undoStatus !== "canceled") {
          notUpdated[subId] = {
            type:        "invalidProperties",
            properties:  ["undoStatus"],
            description: "only undoStatus='canceled' is honored",
          };
          continue;
        }
        if (typeof opts.onCancel !== "function") {
          notUpdated[subId] = {
            type: "cannotUnsend",
            description: "undo not supported (opts.onCancel was not configured)",
          };
          continue;
        }
        try {
          var ok = await opts.onCancel(subId, accountId);
          if (ok) updated[subId] = null;
          else notUpdated[subId] = { type: "cannotUnsend" };
        } catch (err) {
          notUpdated[subId] = _jmapErrorShape(err);
        }
      }
    }

    if (Array.isArray(args.destroy)) {
      for (var di = 0; di < args.destroy.length; di += 1) {
        var destroyId = args.destroy[di];
        if (typeof destroyId !== "string" || destroyId.length === 0) {
          notDestroyed[String(destroyId)] = { type: "invalidArguments" };
          continue;
        }
        if (typeof opts.onDestroyed === "function") {
          try {
            await opts.onDestroyed(destroyId, accountId);
            destroyed.push(destroyId);
          } catch (err) {
            notDestroyed[destroyId] = _jmapErrorShape(err);
          }
        } else {
          destroyed.push(destroyId);
        }
      }
    }

    _emit("mail.jmap.emailsubmission.set", {
      accountId:   accountId,
      created:     Object.keys(created).length,
      notCreated:  Object.keys(notCreated).length,
      updated:     Object.keys(updated).length,
      notUpdated:  Object.keys(notUpdated).length,
      destroyed:   destroyed.length,
      notDestroyed: Object.keys(notDestroyed).length,
    });

    return {
      accountId:    accountId,
      oldState:     args.ifInState || null,
      newState:     bCrypto.generateToken(16),
      created:      Object.keys(created).length     > 0 ? created     : null,
      notCreated:   Object.keys(notCreated).length  > 0 ? notCreated  : null,
      updated:      Object.keys(updated).length     > 0 ? updated     : null,
      notUpdated:   Object.keys(notUpdated).length  > 0 ? notUpdated  : null,
      destroyed:    destroyed.length                > 0 ? destroyed   : null,
      notDestroyed: Object.keys(notDestroyed).length > 0 ? notDestroyed : null,
    };
  };

  async function _processCreate(actor, accountId, sub) {
    if (!sub || typeof sub !== "object" || Array.isArray(sub)) {
      throw _err("invalidArguments", "EmailSubmission must be an object");
    }
    if (typeof sub.identityId !== "string" || sub.identityId.length === 0) {
      throw _err("invalidProperties", "identityId is required", ["identityId"]);
    }
    if (typeof sub.emailId !== "string" || sub.emailId.length === 0) {
      throw _err("invalidProperties", "emailId is required", ["emailId"]);
    }
    if (!sub.envelope || typeof sub.envelope !== "object" || Array.isArray(sub.envelope)) {
      throw _err("invalidProperties", "envelope is required", ["envelope"]);
    }
    var mailFrom = sub.envelope.mailFrom;
    if (!mailFrom || typeof mailFrom !== "object" || typeof mailFrom.email !== "string") {
      throw _err("invalidProperties", "envelope.mailFrom.email is required", ["envelope/mailFrom"]);
    }
    if (!Array.isArray(sub.envelope.rcptTo) || sub.envelope.rcptTo.length === 0) {
      throw _err("noRecipients", "envelope.rcptTo must contain at least one Address");
    }
    if (sub.envelope.rcptTo.length > maxRecipients) {
      throw _err("tooManyRecipients", "rcptTo exceeds " + maxRecipients);
    }
    var rcptEmails = [];
    for (var ri = 0; ri < sub.envelope.rcptTo.length; ri += 1) {
      var r = sub.envelope.rcptTo[ri];
      if (!r || typeof r.email !== "string" || r.email.indexOf("@") <= 0) {
        throw _err("invalidRecipients", "envelope.rcptTo[" + ri + "].email malformed");
      }
      rcptEmails.push(r.email);
    }

    var identList = opts.identities(accountId) || [];
    var identity = null;
    for (var ii = 0; ii < identList.length; ii += 1) {
      if (identList[ii].id === sub.identityId) { identity = identList[ii]; break; }
    }
    if (!identity) {
      throw _err("identityNotFound", "no identity " + sub.identityId + " for account " + accountId);
    }
    if (!mailServerNet.identityCovers(identity.email, mailFrom.email, identityMatchOpts)) {
      throw _err("forbiddenMailFrom",
        "envelope.mailFrom.email is not an address identity " + identity.id + " authorizes");
    }

    var rfc822 = await opts.lookupEmail(sub.emailId, accountId, actor);
    if (rfc822 == null) {
      throw _err("emailNotFound", "emailId " + sub.emailId + " not found");
    }
    var headerFrom = _fromHeaderAddress(rfc822);
    var authors = headerFrom === null ? [null]
                : (Array.isArray(headerFrom) ? headerFrom : [headerFrom]);
    if (authors.length === 0) authors = [null];
    for (var a = 0; a < authors.length; a += 1) {
      if (mailServerNet.identityCovers(identity.email, authors[a], identityMatchOpts)) continue;
      throw _err("forbiddenFrom",
        "the message's From header names an address identity " + identity.id +
        " does not authorize");
    }

    var deliverResult = await opts.deliver({
      from:   mailFrom.email,
      to:     rcptEmails,
      rfc822: rfc822,
    });

    var deliveryStatus = Object.create(null);
    var delivered = deliverResult && deliverResult.delivered  ? deliverResult.delivered : [];
    var deferred  = deliverResult && deliverResult.deferred   ? deliverResult.deferred  : [];
    var failed    = deliverResult && deliverResult.failed     ? deliverResult.failed    : [];
    for (var ddi = 0; ddi < delivered.length; ddi += 1) {
      deliveryStatus[delivered[ddi].recipient] = {
        smtpReply: delivered[ddi].smtpReply || "250 Accepted",
        delivered: "yes",
        displayed: "unknown",
      };
    }
    for (var dfi = 0; dfi < deferred.length; dfi += 1) {
      deliveryStatus[deferred[dfi].recipient] = {
        smtpReply: deferred[dfi].smtpReply || "451 Temporary failure",
        delivered: "queued",
        displayed: "unknown",
      };
    }
    for (var ffi = 0; ffi < failed.length; ffi += 1) {
      deliveryStatus[failed[ffi].recipient] = {
        smtpReply: failed[ffi].smtpReply || "550 Permanent failure",
        delivered: "no",
        displayed: "unknown",
      };
    }

    var newId = bCrypto.generateToken(12);
    return {
      id:             newId,
      identityId:     sub.identityId,
      emailId:        sub.emailId,
      threadId:       sub.threadId || null,
      envelope:       sub.envelope,
      sendAt:         new Date().toISOString(),
      undoStatus:     "final",
      deliveryStatus: deliveryStatus,
      dsnBlobIds:     [],
      mdnBlobIds:     [],
    };
  }

  function _err(type, description, properties) {
    var e = new MailServerJmapError("urn:ietf:params:jmap:error:" + type, description);
    e._jmapType = type;
    if (properties) e._jmapProperties = properties;
    return e;
  }

  function _jmapErrorShape(err) {
    if (err && err._jmapType) {
      var shape = { type: err._jmapType };
      if (err.message) shape.description = err.message;
      if (err._jmapProperties) shape.properties = err._jmapProperties;
      return shape;
    }
    return { type: "serverFail", description: (err && err.message) || String(err) };
  }

  function _emit(action, metadata) {
    try {
      audit().safeEmit({ action: action, outcome: "success", metadata: metadata || {} });
    } catch (_e) { /* drop-silent */ }
  }
}

module.exports = {
  create:                     create,
  emailBodyProperties:        emailBodyProperties,
  emailSubmissionSetHandler:  emailSubmissionSetHandler,
  MailServerJmapError:        MailServerJmapError,
};
