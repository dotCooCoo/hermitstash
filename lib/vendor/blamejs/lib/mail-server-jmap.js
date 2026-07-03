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
 *     mailStore:           b.mailStore.create({ backend: b.db.handle() }),
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
 *   and the standard error mapping (RFC 8620 §3.6.1). Operators wire
 *   the actual method implementations — JMAP semantics are too varied
 *   (Mailbox / Email / Thread / SearchSnippet / Identity /
 *   EmailSubmission) to enshrine in v1.
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
 *   Enforced via `b.guardJmap.validate` — `maxCallsInRequest`,
 *   `maxSizeRequest`, `maxObjectsInGet/Set`, `maxBackRefDepth`. Per-
 *   account method-call concurrent cap via `b.mail.server.rateLimit`
 *   when wired.
 *
 *   ## Error vocabulary (RFC 8620 §3.6.1)
 *
 *   Standard errors emitted as the methodResponse object:
 *
 *     - `urn:ietf:params:jmap:error:requestTooLarge`
 *     - `urn:ietf:params:jmap:error:invalidArguments`
 *     - `urn:ietf:params:jmap:error:invalidResultReference`
 *     - `urn:ietf:params:jmap:error:unknownCapability`
 *     - `urn:ietf:params:jmap:error:limit/<name>`
 *     - `urn:ietf:params:jmap:error:forbidden`
 *     - `urn:ietf:params:jmap:error:accountNotFound`
 *     - `urn:ietf:params:jmap:error:serverFail` (opaque last-resort)
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
var bCrypto = require("./crypto");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var websocket = require("./websocket");
var validateOpts = require("./validate-opts");
var guardJmap = require("./guard-jmap");
var mailServerRegistry = require("./mail-server-registry");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var auditEmit = require("./audit-emit");

var MailServerJmapError = defineClass("MailServerJmapError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";
void C;                                                                                               // reserved for future cap constants

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
 *   profile:             "strict" | "balanced" | "permissive",
 *   posture:             "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   audit:               b.audit                                       // optional
 *
 * @example
 *   var jmap = b.mail.server.jmap.create({
 *     mailStore: b.mailStore.create({ backend: b.db.handle() }),
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

  // JMAP method registry. Wrap operator-supplied `opts.methods` map
  // through `b.mail.serverRegistry` so per-handler resource budgets
  // (maxHandlerBytes / maxHandlerMs) apply uniformly across the IMAP
  // / JMAP / ManageSieve listeners. Legacy `opts.methods` callers get
  // an auto-default budget (10 MiB / 30s) with a one-time deprecation
  // audit event per process; new callers use `opts.overrides` with
  // explicit budgets per the stricter-mode register contract.
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
      allowExperimental: true,   // legacy callers wired anything; preserve the openness
    };
  }
  var registry = mailServerRegistry.create({
    protocol:      "jmap",
    defaults:      defaults,
    overrides:     opts.overrides || {},
    // b.agent.tenant adoption (v0.10.12). When `opts.tenantScope` is
    // supplied, every method dispatch first gates on
    // `tenantScope.check(state.actor, agentTenantId)` — JMAP's
    // accountId scoping continues to apply inside operator handlers.
    tenantScope:   opts.tenantScope   || null,
    agentTenantId: opts.agentTenantId || null,
  });
  var sessionState = bCrypto.generateToken(16);                                                       // opaque session-state token length

  var _emit = auditEmit.emit;

  // ---- Back-reference resolution (RFC 8620 §3.7) -------------------------
  //
  // Walks the args tree replacing `#<refClientId>/<jsonPointer>` shapes
  // with the resolved value from the prior method-response. Returns the
  // resolved args object on success or throws an
  // `urn:ietf:params:jmap:error:invalidResultReference`.
  function _resolveBackRefs(args, priorResponses) {
    if (args === null || typeof args !== "object") return args;
    if (Array.isArray(args)) {
      var out = [];
      for (var i = 0; i < args.length; i += 1) out.push(_resolveBackRefs(args[i], priorResponses));
      return out;
    }
    var obj = {};
    var keys = Object.keys(args);
    for (var k = 0; k < keys.length; k += 1) {
      var key = keys[k];
      var val = args[key];
      if (key.charCodeAt(0) === 0x23) {                                                              // `#` (0x23) is the JMAP back-ref-key prefix
        // `#<srcClientId>` → key strips the `#`; value is { resultOf, name, path }
        var targetKey = key.slice(1);
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
        var resolved = _pointerLookup(src.result, val.path);
        if (resolved === undefined) {
          throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidResultReference",
            "back-ref `#" + targetKey + "` → path '" + val.path + "' resolved to undefined");
        }
        obj[targetKey] = resolved;
      } else {
        obj[key] = _resolveBackRefs(val, priorResponses);
      }
    }
    return obj;
  }

  // Minimal JSON Pointer (RFC 6901 §3) — `/foo/bar/0` traversal. JMAP
  // back-references constrain the shape (single object → single array
  // → single field) so we don't need the full RFC 6901 escape grammar
  // here. Bounded recursion via the back-ref-depth cap upstream.
  function _pointerLookup(node, path) {
    if (typeof path !== "string") return undefined;
    if (path === "" || path === "/") return node;
    var parts = path.split("/");
    var cur = node;
    for (var i = 0; i < parts.length; i += 1) {
      var seg = parts[i];
      if (seg === "" && i === 0) continue;
      if (cur === null || typeof cur !== "object") return undefined;
      // RFC 6901 ~1 / ~0 escapes — minimal grammar.
      seg = seg.replace(/~1/g, "/").replace(/~0/g, "~");                                              // allow:regex-no-length-cap — seg length bounded by path which is bounded by maxLineBytes upstream
      if (Array.isArray(cur)) {
        if (seg === "*") return cur;
        var idx = parseInt(seg, 10);
        if (!isFinite(idx) || idx < 0 || idx >= cur.length) return undefined;
        cur = cur[idx];
      } else {
        if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
        cur = cur[seg];
      }
    }
    return cur;
  }

  // ---- Account authorization (RFC 8620 §3.6.1 accountNotFound) ------------
  //
  // The set of accountIds an actor may touch is whatever
  // `opts.accountsFor(actor)` enumerates in its `accounts` map — the same
  // source the session resource advertises. Resolving it ONCE per request
  // and rejecting any client-supplied accountId outside that set is the
  // cross-tenant authorization control: without it, a tenant's request can
  // name another tenant's accountId and reach the operator's method/blob
  // handler, which must then independently re-check or leak. The listener
  // owns this gate so every account-scoped op (method dispatch + blob
  // upload/download) is covered uniformly.
  async function _permittedAccountIds(actor) {
    var info = await opts.accountsFor(actor);
    info = info || {};
    var accounts = info.accounts || {};
    // A Set of the accountIds the actor is enumerated for. An empty/garbage
    // accounts map yields an empty set → every account-scoped reference is
    // rejected (fail-closed), which is the correct posture for an actor the
    // operator declined to grant any account.
    var set = Object.create(null);
    if (accounts && typeof accounts === "object") {
      var ids = Object.keys(accounts);
      for (var i = 0; i < ids.length; i += 1) set[ids[i]] = true;
    }
    return set;
  }

  // ---- Dispatch ------------------------------------------------------------
  //
  // `dispatch(actor, body)` is the operator-callable form — accepts a
  // pre-parsed request body + an authenticated actor, returns a
  // response object suitable for JSON-serialization to the client.
  async function dispatch(actor, body) {
    if (!actor) {
      return _refusalResponse("urn:ietf:params:jmap:error:forbidden",
        "actor is required (operator must wire b.middleware.bearerAuth before this handler)");
    }
    var parsed;
    try {
      parsed = guardJmap.validate(body, {
        profile: profile,
        posture: posture,
        serverCapabilities: serverCapabilities,
      });
    } catch (e) {
      var errType = (e && e.code) || "urn:ietf:params:jmap:error:invalidArguments";
      _emit("mail.server.jmap.request_refused",
        { type: errType, reason: (e && e.message) || "" }, "denied");
      return _refusalResponse(errType, (e && e.message) || "request refused");
    }

    // Resolve the actor's permitted accountId set ONCE for the whole
    // request (RFC 8620 §3.6.1). Every account-scoped method call is gated
    // against it below, BEFORE the operator handler runs, so a client can't
    // name another tenant's accountId and reach the backend.
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
    var byClientId = Object.create(null);
    for (var i = 0; i < parsed.methodCalls.length; i += 1) {
      var call = parsed.methodCalls[i];
      var methodName = call[0];
      var rawArgs    = call[1];
      var clientId   = call[2];
      var resolvedArgs;
      try {
        resolvedArgs = _resolveBackRefs(rawArgs, byClientId);
      } catch (e) {
        var refType = (e && e.code) || "urn:ietf:params:jmap:error:invalidResultReference";
        methodResponses.push(["error", { type: refType, description: (e && e.message) || "" }, clientId]);
        continue;
      }
      if (!registry.has(methodName)) {
        methodResponses.push(["error",
          { type: "urn:ietf:params:jmap:error:unknownMethod",
            description: "Method '" + methodName + "' not implemented on this server" }, clientId]);
        continue;
      }
      // Cross-tenant gate (RFC 8620 §3.6.1): EVERY account-id argument the call
      // names MUST be one the actor is enumerated for — not only `accountId`
      // but also `fromAccountId` on /copy methods (Email/copy, CalendarEvent/copy
      // — RFC 8620 §5.4), whose SOURCE account is read from. Checking only the
      // destination accountId let a /copy name a foreign fromAccountId and copy
      // (read) another tenant's data. Rejected BEFORE the operator handler runs.
      // Account-agnostic methods (no *AccountId arg) pass through unchanged.
      if (resolvedArgs && typeof resolvedArgs === "object") {
        var argKeys = Object.keys(resolvedArgs);
        var deniedAccountId; var deniedHit = false;
        for (var aki = 0; aki < argKeys.length && !deniedHit; aki += 1) {
          if (!/[Aa]ccountId$/.test(argKeys[aki])) continue;       // accountId, fromAccountId, ...
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
            { type: "urn:ietf:params:jmap:error:accountNotFound",
              description: "accountId is not accessible to this actor" }, clientId]);
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
        // JMAP methodCalls execute sequentially by spec (RFC 8620 §3.7 —
        // back-references require strict ordering). The await-in-loop
        // pattern is intentional here.
        var result = await registry.dispatch(methodName, actor, resolvedArgs, {
          using:       parsed.using,
          createdIds:  parsed.createdIds,
          methodName:  methodName,
          clientId:    clientId,
        });
        if (result && typeof result === "object" && result.type &&
            typeof result.type === "string" && result.type.indexOf("urn:ietf:params:jmap:error:") === 0) {
          // Operator-emitted error shape — preserve as-is.
          methodResponses.push(["error", result, clientId]);
          byClientId[clientId] = { name: "error", result: result };
        } else {
          methodResponses.push([methodName, result || {}, clientId]);
          byClientId[clientId] = { name: methodName, result: result || {} };
        }
      } catch (e) {
        _emit("mail.server.jmap.method_threw",
          { method: methodName, clientId: clientId,
            error: (e && e.message) || String(e) }, "failure");
        methodResponses.push(["error",
          { type: "urn:ietf:params:jmap:error:serverFail",
            description: "Method threw" }, clientId]);
      }
    }

    _emit("mail.server.jmap.request",
      { methodCallCount: parsed.methodCalls.length, using: parsed.using });

    return {
      methodResponses: methodResponses,
      sessionState:    sessionState,
      createdIds:      parsed.createdIds,
    };
  }

  function _refusalResponse(type, description) {
    return {
      type:        type,
      description: description,
      methodResponses: [],
      sessionState: sessionState,
    };
  }

  // ---- HTTP handlers -----------------------------------------------------

  function apiHandler(req, res) {
    // Operator wires b.middleware.bearerAuth before this handler, so
    // `req.user` is the authenticated actor. If req.user is missing,
    // refuse with 401 + Problem Details body.
    var actor = req.user || (req.actor || null);
    var rawBody = req.body;
    if (rawBody === undefined) {
      // b.middleware.bodyParser may not have run. Refuse cleanly.
      res.statusCode = 400;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:invalidArguments",
        description: "request body missing (wire b.middleware.bodyParser before this handler)",
      }));
      return;
    }
    dispatch(actor, rawBody).then(function (response) {
      // Map typed JMAP refusals to the right HTTP status. `forbidden`
      // means the dispatcher refused because actor was missing /
      // wrong-tenant — clients + proxies need 401 to trigger their
      // re-auth flow (a 400 looks like a malformed request, which it
      // isn't). Everything else stays 400 per RFC 8620 §3.6.1.
      if (response && response.type === "urn:ietf:params:jmap:error:forbidden") {
        res.statusCode = 401;                                                                        // HTTP status codes
      } else if (response && response.type) {
        res.statusCode = 400;                                                                        // HTTP status codes
      } else {
        res.statusCode = 200;                                                                        // HTTP status codes
      }
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(response));
    }, function (err) {
      _emit("mail.server.jmap.handler_threw",
        { error: (err && err.message) || String(err) }, "failure");
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:serverFail",
        description: "Server error",
      }));
    });
  }

  // _requireActor(req, res) — resolve the authenticated actor; on absence,
  // write the RFC 8620 401 forbidden Problem-Details body and return null so
  // the caller returns. Shared by every JMAP handler that gates on actor.
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

  // _forEachQueryParam(query, fn) — split a raw URL query string on "&" and
  // hand each non-empty pair to fn(rawKey, rawValue): the key is the text
  // before the first "=", the value the remainder (both still
  // percent-encoded — the caller decodes the slices it keeps).
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
        // RFC 8887 §3 — advertise the WebSocket transport in the
        // capabilities object so RFC-compliant clients discover the
        // endpoint via the canonical session-discovery flow rather
        // than depending on the top-level `webSocketUrl` alias.
        var defaultCaps = { "urn:ietf:params:jmap:core": {} };
        var hasOperatorWsCap = Object.prototype.hasOwnProperty.call(
          serverCapabilities, "urn:ietf:params:jmap:websocket");
        if (!hasOperatorWsCap) {
          defaultCaps["urn:ietf:params:jmap:websocket"] = {
            url:          opts.webSocketUrl || "/jmap/ws",
            supportsPush: true,
          };
        }
        var session = {
          capabilities: Object.assign({}, defaultCaps, serverCapabilities),
          accounts:     info.accounts || {},
          primaryAccounts: info.primaryAccounts || {},
          username:     actor.username || actor.id || "unknown",
          apiUrl:       opts.apiUrl       || "/jmap/api",
          downloadUrl:  opts.downloadUrl  || "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
          uploadUrl:    opts.uploadUrl    || "/jmap/upload/{accountId}",
          eventSourceUrl: opts.eventSourceUrl || "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
          // RFC 8887 §3 — `webSocketUrl` advertises the JMAP WS
          // endpoint. Operator overrides via opts.webSocketUrl; default
          // mounts at `/jmap/ws`.
          urlEndpointResolution: serverCapabilities["urn:ietf:params:jmap:websocket"]
            ? { useEndpoint: opts.webSocketUrl || "/jmap/ws", urlPrefix: "" }
            : undefined,
          webSocketUrl:   opts.webSocketUrl || "/jmap/ws",
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

  // RFC 8620 §7.3 — EventSource (Server-Sent Events) push channel.
  // Clients connect to `/jmap/eventsource?types=...&closeafter=...&ping=N`.
  // Server holds the connection open and writes `event: state` + JSON
  // payloads when the operator backend reports a state change.
  // Periodic `event: ping` keeps intermediate proxies / load-balancers
  // from closing the idle connection.
  //
  // closeafter=state — close after first state event (poll-like).
  // closeafter=no (default) — keep open until disconnect.
  // ping=<seconds> — keepalive interval (default 30s, min 5s, max 900s).
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
    // Parse query params from the URL. The HTTP server hands `req.url`
    // with the query intact; we don't depend on Node's URL constructor
    // for the query-string parse — small inline scan is enough.
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
      : typesStr.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
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
    // RFC 8620 §7.3 — `ping=0` is the EXPLICIT opt-out for the
    // keepalive event channel. Treat it as "no ping" rather than
    // clamping to the default. Any other non-finite / out-of-band
    // value falls back to the 30 s default; in-band values
    // (5..900 s) pass through unchanged so clients see the same
    // negotiated interval they requested.
    var pingN;
    var pingDisabled = false;
    if (params.ping === "0") {
      pingDisabled = true;
      pingN = 0;
    } else {
      pingN = parseInt(params.ping, 10);
      if (!isFinite(pingN) || pingN < 5) pingN = 30;                                                   // RFC 8620 §7.3 default ping seconds
      if (pingN > 900) pingN = 900;                                                                    // allow:raw-time-literal — explicit max-ping cap (15 minutes)
    }

    // SSE wire headers per the HTML5 spec § "Server-sent events"
    // and RFC 8620 §7.3 — Content-Type MUST be `text/event-stream`,
    // intermediates MUST NOT cache (`Cache-Control: no-cache`),
    // `Connection: keep-alive` instructs proxies to leave it open.
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");                                                          // disables nginx response buffering on the EventSource stream
    // Initial event tells the client the stream is alive + carries
    // the current session state so a fresh subscriber can compare
    // against its cached `state` to know whether a missed update
    // happened during the (re)connect.
    res.write("retry: 5000\n\n");                                                                      // SSE reconnect-after hint (5s)
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
        // Socket already torn down — clean up.
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
      // RFC 8620 §7.3 — ping payload carries `{ "interval": <N> }` so
      // clients can detect stale connections via interval drift and
      // tell whether the server clamped their requested value.
      var pingPayload = JSON.stringify({ interval: pingN });
      try { res.write("event: ping\ndata: " + pingPayload + "\n\n"); }
      catch (_e) { _cleanup(); }
    }

    // Operator-supplied emit-fn — the backend pushes
    // { kind: "StateChange", changed: { <accountId>: { <type>: <state> } } }
    // events into the SSE stream. The listener formats per RFC 8620
    // §7.4 — `event: state` carries the StateChange object body.
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

  // RFC 8620 §6.1 — blob upload. Operators POST raw bytes to
  // `/jmap/upload/{accountId}` with `Content-Type` set to the
  // blob MIME type. The handler streams the request body into a
  // bounded buffer, calls `mailStore.uploadBlob(actor, accountId,
  // contentType, bytes)`, and returns the JSON descriptor
  // `{ accountId, blobId, type, size }` the client uses in
  // subsequent Email/set / Email/import calls.
  //
  // Path parameters are extracted from the URL; the operator-side
  // HTTP router MUST mount this handler at a prefix that exposes
  // the accountId segment (e.g. `/jmap/upload/:accountId`). The
  // handler defensively re-parses the URL in case the router didn't
  // populate `req.params`.
  var DEFAULT_MAX_BLOB_BYTES = opts.maxBlobBytes || (50 * 1024 * 1024);                                // allow:raw-byte-literal — 50 MiB default blob upload cap
  // RFC 8620 §1.2 — JMAP `Id` is a non-empty string of < 256 octets in
  // `[A-Za-z0-9_-]`. The earlier shape capped at 64 chars which refused
  // legitimate-shape accounts; widen to the full spec maximum.
  var MAX_JMAP_ID_LEN = 255;                                                                           // RFC 8620 §1.2 Id max length
  var JMAP_ID_RE      = /^[A-Za-z0-9_-]{1,255}$/;
  // Anti-polynomial: bound the URL length BEFORE any regex / split runs
  // (CodeQL flags `\/+` on uncontrolled input). Headers + URL paths in
  // practice stay well under 8 KiB; over-long URLs refuse outright.
  var MAX_URL_LEN     = 8192;                                                                          // 8 KiB URL cap

  // Strip a query string + walk the path producing non-empty segments,
  // WITHOUT any unbounded regex. Returns an empty array when the URL
  // is over the cap so the caller can refuse with 400.
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
      if (ch === 0x2f) {                                                                               // '/' (0x2f)
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
    // Extract accountId from URL path. The mount path is
    // `/jmap/upload/{accountId}`; the operator's router may strip
    // the `/jmap/upload/` prefix (so segments == [accountId]) OR
    // pass through the full path. Either shape gives the trailing
    // segment as accountId — but the WHOLE URL must split cleanly
    // (`_splitPathSegments` refuses over-long input).
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
    var contentType = req.headers && req.headers["content-type"]
      ? String(req.headers["content-type"]).split(";")[0].trim()
      : "application/octet-stream";
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    DEFAULT_MAX_BLOB_BYTES,
      errorClass:  MailServerJmapError,
      sizeCode:    "mail-server-jmap/blob-too-large",
      sizeMessage: "Blob exceeds maxSizeUpload (" + DEFAULT_MAX_BLOB_BYTES + " bytes)",
    });
    var refused = false;

    req.on("data", function (chunk) {
      if (refused) return;
      try { collector.push(chunk); }
      catch (_e) {
        refused = true;
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
      var bytes = collector.result();
      Promise.resolve()
        // Cross-tenant gate (RFC 8620 §3.6.1): the accountId in the upload
        // URL must be one the actor is enumerated for, else accountNotFound
        // — the foreign accountId never reaches uploadBlob.
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
        });
    });

    function _completeUpload(bytes) {
      return Promise.resolve()
        .then(function () { return opts.mailStore.uploadBlob(actor, accountId, contentType, bytes); })
        .then(function (meta) {
          if (!meta || typeof meta !== "object" || typeof meta.blobId !== "string") {
            throw new MailServerJmapError("mail-server-jmap/bad-upload-result",
              "uploadBlob backend MUST return { blobId, type?, size? }");
          }
          res.statusCode = 201;                                                                        // HTTP 201 Created
          res.setHeader("Content-Type", "application/json; charset=utf-8");
          res.end(JSON.stringify({
            accountId: accountId,
            blobId:    meta.blobId,
            type:      meta.type || contentType,
            size:      typeof meta.size === "number" ? meta.size : bytes.length,
          }));
        });
      // Errors from uploadBlob propagate to the req.on("end") chain's
      // .catch (single serverFail responder, headersSent-guarded).
    }
    req.on("error", function () {
      if (!refused) {
        refused = true;
        try { res.statusCode = 400; res.end(); }                                                       // HTTP 400
        catch (_e) { /* silent-catch: socket already torn down */ }
      }
    });
  }

  // RFC 8620 §6.2 — blob download. GET `/jmap/download/{accountId}/
  // {blobId}/{name}?accept={type}`. Backend hook returns a stream-
  // shaped buffer (Buffer or async-iterable) + the canonical MIME
  // type; the handler pipes it to the response.
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
    var qIdx2 = rawUrl.indexOf("?");
    var query = qIdx2 === -1 ? "" : rawUrl.slice(qIdx2 + 1);
    var acceptType = "";
    _forEachQueryParam(query, function (k, v) {
      if (k === "accept") {
        try { acceptType = decodeURIComponent(v); } catch (_e) { /* silent-catch: malformed % encoding */ }
      }
    });
    // Path parsing — `/jmap/download/{accountId}/{blobId}/{name}`. The
    // operator's router may strip the `/jmap/download/` prefix, so
    // valid segment counts are EXACTLY 3 (router-stripped) OR 5+ AND
    // starting with `jmap` + `download`. Anything else refuses BEFORE
    // a tail-segment remap could land path tokens in the wrong
    // accountId / blobId / name slots.
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
      fileName  = pathSegs[2];
    } else if (pathSegs.length >= 5 &&
               pathSegs[pathSegs.length - 5].toLowerCase() === "jmap" &&
               pathSegs[pathSegs.length - 4].toLowerCase() === "download") {
      accountId = pathSegs[pathSegs.length - 3];
      blobId    = pathSegs[pathSegs.length - 2];
      fileName  = pathSegs[pathSegs.length - 1];
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
      // Cross-tenant gate (RFC 8620 §3.6.1): the accountId in the download
      // URL must be one the actor is enumerated for, else accountNotFound —
      // the foreign accountId never reaches downloadBlob.
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
        var bType  = result.type || acceptType || "application/octet-stream";
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
        // RFC 5987 — operator may want to surface fileName via
        // Content-Disposition. Default to attachment when the
        // download is a non-text type.
        if (fileName && /^[A-Za-z0-9._-]{1,200}$/.test(fileName)) {
          res.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        }
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

  // RFC 8887 — JMAP over WebSocket. The session-resource's `webSocketUrl`
  // points at this handler. Client opens a WS connection with the `jmap`
  // subprotocol; bidirectional JSON frames carry `{ "@type": "Request" }`
  // / `{ "@type": "WebSocketPushEnable" }` / `{ "@type":
  // "WebSocketPushDisable" }` from the client, and `{ "@type":
  // "Response" }` / `{ "@type": "StateChange" }` / `{ "@type":
  // "RequestError" }` from the server.
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
      maxMessageBytes: opts.webSocketMaxMessageBytes || (10 * 1024 * 1024),                            // allow:raw-byte-literal — 10 MiB JMAP WS message cap
      // permessage-deflate is off by default — same CRIME-class threat
      // model as the IMAP COMPRESS=DEFLATE intentional skip in v0.11.28.
      // Operators opt in via opts.webSocketPermessageDeflate.
      permessageDeflate: opts.webSocketPermessageDeflate === true,
    });
    if (!conn) return null;
    // RFC 8887 §3.1 — server MUST select `jmap` if offered. Refuse the
    // connection cleanly if subprotocol negotiation came back null.
    if (conn.subprotocol !== "jmap") {
      try { conn.close(1002, "RFC 8887 requires Sec-WebSocket-Protocol: jmap"); }                      // RFC 6455 protocol-error close code
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

    function _sendRequestError(requestId, type, description) {
      _sendJson({
        "@type":       "RequestError",
        requestId:     requestId || null,
        type:          type,
        description:   description,
      });
    }

    conn.on("message", function (data, isBinary) {
      if (isBinary) {
        _sendRequestError(null,
          "urn:ietf:params:jmap:error:notJSON",
          "WebSocket frame must be a JSON text frame (RFC 8887 §4)");
        return;
      }
      var text = data.toString("utf8");
      // Byte cap measured on the raw frame buffer, not text.length (UTF-16
      // code units) — a multibyte payload is 2-4x larger in bytes than chars,
      // so a char-length check under-enforces the limit.
      if (data.length > (opts.webSocketMaxMessageBytes || (10 * 1024 * 1024))) {                       // allow:raw-byte-literal — mirrors handleUpgrade cap
        _sendRequestError(null,
          "urn:ietf:params:jmap:error:limit",
          "WebSocket message exceeds maxSizeRequest");
        return;
      }
      var parsed;
      try { parsed = safeJson.parse(text, { maxBytes: opts.webSocketMaxMessageBytes || (10 * 1024 * 1024) }); } // allow:raw-byte-literal — mirrors handleUpgrade cap
      catch (_e) {
        _sendRequestError(null,
          "urn:ietf:params:jmap:error:notJSON",
          "WebSocket frame is not valid JSON");
        return;
      }
      var type = parsed && parsed["@type"];
      var requestId = parsed && parsed.id;

      if (type === "Request") {
        // RFC 8887 §4 — `Request` carries the same body as the HTTP
        // POST: `{ using, methodCalls, createdIds? }`. Dispatch
        // through the existing dispatch path; response is wrapped in
        // `{ "@type": "Response", requestId, methodResponses, createdIds? }`.
        // EXCEPT when dispatch returns a refusal shape — request-
        // level validation failure (`{ type, description,
        // methodResponses: [] }`) — those MUST surface as
        // `{ "@type": "RequestError" }` so the client can distinguish
        // an invalid request from a valid empty-result Response.
        Promise.resolve()
          .then(function () { return dispatch(actor, parsed); })
          .then(function (rv) {
            if (rv && typeof rv.type === "string" && typeof rv.description === "string") {
              _sendRequestError(requestId, rv.type, rv.description);
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
        // RFC 8887 §5 — duplicate enable is a no-op. Also refuse
        // mid-subscription concurrency: if a previous PushEnable hasn't
        // resolved yet, the second is treated as no-op. Without this
        // gate a fast-firing enable/disable/enable sequence could
        // leak duplicate backend subscriptions OR end up with an
        // un-unsubscribed handle when connection closes.
        if (pushEnabled) return;
        // SYNC flip: gate concurrent PushEnable calls before the
        // async subscribePush resolves. PushDisable / close that
        // arrive in the gap see pushEnabled=true + a pending
        // pushSetupPromise; the setup promise's `then` handles the
        // late-cleanup case via the connClosed flag.
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
            // Late cleanup: if Disable / close arrived in the setup
            // gap, run the unsubscribe immediately.
            if ((connClosed || !pushEnabled) && typeof pushUnsubscribe === "function") {
              try { pushUnsubscribe(); }
              catch (_e) { /* silent-catch: drop-silent — unsubscribe is best-effort */ }
              pushUnsubscribe = null;
            }
          })
          .catch(function (err) {
            // Setup failed — roll back the sync flip so a retry can
            // succeed, and surface the error to the operator client.
            pushEnabled = false;
            _sendRequestError(null,
              "urn:ietf:params:jmap:error:serverFail",
              (err && err.message) || "subscribePush threw");
          });
        return;
      }

      if (type === "WebSocketPushDisable") {
        // Mark disabled first so an in-flight subscribePush sees
        // pushEnabled=false in its late-cleanup branch.
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
      // SYNC flip — an in-flight subscribePush.then() observes
      // connClosed=true and runs the late-cleanup unsubscribe path.
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
    // RFC 8620 §2.2 — well-known endpoint redirects (or directly returns)
    // the session URL. We redirect to /jmap/session per the most common
    // pattern; operators with a non-root mount path override via
    // opts.sessionUrl.
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
  var maxRecipients = opts.maxRecipients || 1000;                                                       // recipient cap mirrors b.mail.send.deliver
  if (typeof maxRecipients !== "number" || !isFinite(maxRecipients) || maxRecipients < 1) {
    throw new MailServerJmapError("mail-server-jmap/bad-max-recipients",
      "emailSubmissionSetHandler: opts.maxRecipients MUST be a positive integer");
  }

  return async function emailSubmissionSet(actor, args, _ctx) {
    if (!args || typeof args !== "object" || typeof args.accountId !== "string") {
      throw new MailServerJmapError("urn:ietf:params:jmap:error:invalidArguments",
        "EmailSubmission/set: accountId is required");
    }
    var accountId = args.accountId;
    var created     = {};
    var notCreated  = {};
    var updated     = {};
    var notUpdated  = {};
    var destroyed   = [];
    var notDestroyed = {};

    // ---- create branch (RFC 8621 §7.5.1) ----------------------------------
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

    // ---- update branch (RFC 8621 §7.5.2 — undoStatus="canceled" only) -----
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
        // RFC 8621 §7.5.2 — only `undoStatus` is mutable post-create.
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

    // ---- destroy branch (RFC 8621 §7.5.3) ---------------------------------
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
          // No persistence wired — accept the destroy as a noop so the
          // operator's clients can clean up client-side state.
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
      newState:     bCrypto.generateToken(16),                                                          // opaque state token length
      created:      Object.keys(created).length     > 0 ? created     : null,
      notCreated:   Object.keys(notCreated).length  > 0 ? notCreated  : null,
      updated:      Object.keys(updated).length     > 0 ? updated     : null,
      notUpdated:   Object.keys(notUpdated).length  > 0 ? notUpdated  : null,
      destroyed:    destroyed.length                > 0 ? destroyed   : null,
      notDestroyed: Object.keys(notDestroyed).length > 0 ? notDestroyed : null,
    };
  };

  // -------- per-create processing -------------------------------------------
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

    // Identity gate (RFC 8621 §7.5.1.2 forbiddenMailFrom / §7.5.1.3 identityNotFound).
    var identList = opts.identities(accountId) || [];
    var identity = null;
    for (var ii = 0; ii < identList.length; ii += 1) {
      if (identList[ii].id === sub.identityId) { identity = identList[ii]; break; }
    }
    if (!identity) {
      throw _err("identityNotFound", "no identity " + sub.identityId + " for account " + accountId);
    }
    if (identity.email && identity.email !== mailFrom.email) {
      throw _err("forbiddenMailFrom",
        "envelope.mailFrom.email does not match identity " + identity.id);
    }

    // Blob lookup (RFC 8621 §7.5.1.4 emailNotFound).
    var rfc822 = await opts.lookupEmail(sub.emailId, accountId, actor);
    if (rfc822 == null) {
      throw _err("emailNotFound", "emailId " + sub.emailId + " not found");
    }

    // Hand to b.mail.send.deliver.
    var deliverResult = await opts.deliver({
      from:   mailFrom.email,
      to:     rcptEmails,
      rfc822: rfc822,
    });

    // Map deliver result → JMAP deliveryStatus (RFC 8621 §7.4).
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

    var newId = bCrypto.generateToken(12);                                                              // JMAP-server-assigned id
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
  emailSubmissionSetHandler:  emailSubmissionSetHandler,
  MailServerJmapError:        MailServerJmapError,
};
