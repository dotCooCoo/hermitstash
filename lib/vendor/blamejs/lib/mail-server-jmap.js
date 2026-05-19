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
 *   ## What v1 does NOT ship
 *
 *   - **Push channel (SSE + WebSocket per RFC 8887)** — operator wires
 *     `b.sse` or `b.websocket` to the `pushSubscribe` hook. v1.5
 *     bundles a turnkey push handler.
 *   - **Blob upload/download endpoints** — operator wires their own
 *     `/jmap/upload` / `/jmap/download` handlers; the framework
 *     supplies `b.storage` + `b.objectStore` + the guard-* family
 *     for the actual upload path.
 *   - **EmailSubmission (RFC 8621 §7)** — operator wires the bridge
 *     to `b.mail.server.submission`'s outbound agent.
 *   - **Calendars / Contacts (RFC 9610)**, **Sieve (RFC 9404)**,
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
var validateOpts = require("./validate-opts");
var guardJmap = require("./guard-jmap");
var mailServerRegistry = require("./mail-server-registry");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerJmapError = defineClass("MailServerJmapError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";
var WELL_KNOWN_PATH = "/.well-known/jmap";
void C;                                                                                               // reserved for future cap constants
void WELL_KNOWN_PATH;

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
    protocol:  "jmap",
    defaults:  defaults,
    overrides: opts.overrides || {},
  });
  var sessionState = bCrypto.generateToken(16);                                                       // allow:raw-byte-literal — opaque session-state token length

  function _emit(action, metadata, outcome) {
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }

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
      if (key.charCodeAt(0) === 0x23) {                                                              // allow:raw-byte-literal — `#` (0x23) is the JMAP back-ref-key prefix
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
        res.statusCode = 401;                                                                        // allow:raw-byte-literal — HTTP status codes
      } else if (response && response.type) {
        res.statusCode = 400;                                                                        // allow:raw-byte-literal — HTTP status codes
      } else {
        res.statusCode = 200;                                                                        // allow:raw-byte-literal — HTTP status codes
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

  function sessionHandler(req, res) {
    var actor = req.user || (req.actor || null);
    if (!actor) {
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({
        type:        "urn:ietf:params:jmap:error:forbidden",
        description: "Authentication required",
      }));
      return;
    }
    Promise.resolve().then(function () { return opts.accountsFor(actor); })
      .then(function (accountInfo) {
        var info = accountInfo || { primaryAccounts: {}, accounts: {} };
        var session = {
          capabilities: Object.assign({}, { "urn:ietf:params:jmap:core": {} }, serverCapabilities),
          accounts:     info.accounts || {},
          primaryAccounts: info.primaryAccounts || {},
          username:     actor.username || actor.id || "unknown",
          apiUrl:       opts.apiUrl       || "/jmap/api",
          downloadUrl:  opts.downloadUrl  || "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
          uploadUrl:    opts.uploadUrl    || "/jmap/upload/{accountId}",
          eventSourceUrl: opts.eventSourceUrl || "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
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
    MailServerJmapError:  MailServerJmapError,
  };
}

module.exports = {
  create:               create,
  MailServerJmapError:  MailServerJmapError,
};
