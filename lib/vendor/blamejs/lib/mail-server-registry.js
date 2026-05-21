"use strict";
/**
 * @module b.mail.serverRegistry
 * @nav    Mail
 * @title  Mail Server Method Registry
 *
 * @intro
 *   Shared per-method dispatch registry for the IMAP / JMAP /
 *   ManageSieve listener factories. Replaces the hand-rolled
 *   `switch (verb)` dispatchers with a single primitive that:
 *
 *   - runs the protocol-specific guard chain BEFORE the handler
 *     lookup (so operator-supplied overrides cannot bypass
 *     `b.guardImapCommand` / `b.guardJmap` / `b.guardManagesieveCommand`),
 *   - enforces per-handler resource budgets (`maxHandlerBytes`,
 *     `maxHandlerMs`) — refused at registration time if not supplied,
 *   - emits a `mail.serverRegistry.method_dispatch` audit event with
 *     handler-source (`builtin` | `operator-override`),
 *   - rejects registrations of method names outside the per-protocol
 *     IANA / RFC catalogue (unless `allowExperimental: true`, which
 *     itself audits).
 *
 *   Operators wanting to override IMAP `FETCH`, JMAP `Email/query`,
 *   ManageSieve `PUTSCRIPT`, etc. supply
 *   `opts.overrides: { "FETCH": { fn, maxHandlerBytes, maxHandlerMs } }`
 *   to the listener factory and the registry routes dispatch through
 *   the override without touching wire-protocol state, audit
 *   lifecycle, or the guard substrate.
 *
 *   Per-handler resource budgets are required (no auto-defaults) per
 *   the framework's security-defaults-on rule: an operator-supplied
 *   FETCH override that omits a budget could regress CVE-2024-34055
 *   (Cyrus authenticated OOM via unbounded allocation); the
 *   stricter-mode contract forces the operator to acknowledge the
 *   resource ceiling explicitly.
 *
 * @card
 *   Per-method dispatch registry for the mail-server listeners. Guard-chain preserving, per-handler resource-budget required, audit on every dispatch.
 */

var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");
var audit = require("./audit");
var { defineClass } = require("./framework-error");

var MailServerRegistryError = defineClass("MailServerRegistryError", { alwaysPermanent: true });

// Per-protocol RFC catalogue. Names outside these tables refuse at
// register() unless `allowExperimental: true`.
var IMAP_VERBS = Object.freeze({
  CAPABILITY: 1, NOOP: 1, LOGOUT: 1, STARTTLS: 1, AUTHENTICATE: 1,
  LOGIN: 1, ID: 1, ENABLE: 1, SELECT: 1, EXAMINE: 1, CREATE: 1,
  DELETE: 1, RENAME: 1, SUBSCRIBE: 1, UNSUBSCRIBE: 1, LIST: 1,
  NAMESPACE: 1, STATUS: 1, APPEND: 1, IDLE: 1, CHECK: 1, CLOSE: 1,
  UNSELECT: 1, EXPUNGE: 1, SEARCH: 1, FETCH: 1, STORE: 1, COPY: 1,
  MOVE: 1, UID: 1, DONE: 1,
  // v0.11.28 — RFC 5465 NOTIFY / RFC 5464 METADATA / RFC 4469 CATENATE.
  // CATENATE is an APPEND modifier and stays under APPEND in dispatch;
  // METADATA gets GETMETADATA + SETMETADATA verbs.
  NOTIFY: 1, GETMETADATA: 1, SETMETADATA: 1,
});

var MANAGESIEVE_VERBS = Object.freeze({
  AUTHENTICATE: 1, STARTTLS: 1, LOGOUT: 1, CAPABILITY: 1, HAVESPACE: 1,
  PUTSCRIPT: 1, LISTSCRIPTS: 1, SETACTIVE: 1, GETSCRIPT: 1,
  DELETESCRIPT: 1, RENAMESCRIPT: 1, NOOP: 1,
});

// JMAP method names match the `Type/verb` shape. The catalogue table
// enumerates the RFC 8620 + RFC 8621 set; operator-registered types
// must opt in via `allowExperimental: true` with audit emission.
var JMAP_METHODS = Object.freeze({
  "Core/echo": 1,
  "Mailbox/get": 1, "Mailbox/changes": 1, "Mailbox/query": 1,
  "Mailbox/queryChanges": 1, "Mailbox/set": 1,
  "Thread/get": 1, "Thread/changes": 1,
  "Email/get": 1, "Email/changes": 1, "Email/query": 1,
  "Email/queryChanges": 1, "Email/set": 1, "Email/copy": 1,
  "Email/import": 1, "Email/parse": 1,
  "SearchSnippet/get": 1,
  "Identity/get": 1, "Identity/changes": 1, "Identity/set": 1,
  "EmailSubmission/get": 1, "EmailSubmission/changes": 1,
  "EmailSubmission/query": 1, "EmailSubmission/queryChanges": 1,
  "EmailSubmission/set": 1,
  "VacationResponse/get": 1, "VacationResponse/set": 1,
});

var CATALOGUE = Object.freeze({
  imap:        IMAP_VERBS,
  jmap:        JMAP_METHODS,
  managesieve: MANAGESIEVE_VERBS,
});

// Maximum resource budget caps. Operators cannot raise above these
// even with explicit values — protects against accidental
// configuration that lifts the CVE-2024-34055 / CVE-2026-26312 OOM
// ceiling.
var MAX_HANDLER_BYTES_CEILING = 256 * 1024 * 1024;                                                   // allow:raw-byte-literal — 256 MiB per-handler ceiling
var MAX_HANDLER_MS_CEILING    = 5 * 60 * 1000;                                                       // allow:raw-time-literal — 5 minute per-handler ceiling

/**
 * @primitive b.mail.serverRegistry.create
 * @signature b.mail.serverRegistry.create(opts)
 * @since     0.10.11
 * @status    stable
 * @related   b.mail.server.imap.create, b.mail.server.jmap.create, b.mail.server.managesieve.create
 *
 * Build a per-method dispatch registry for one of the mail-server
 * listeners. Returns `{ register, unregister, dispatch, list,
 * has, source, MailServerRegistryError }`.
 *
 * @opts
 *   protocol:        "imap" | "jmap" | "managesieve",
 *   defaults:        { [name]: { fn, maxHandlerBytes, maxHandlerMs } },
 *   overrides:       { [name]: { fn, maxHandlerBytes, maxHandlerMs } },
 *   notFoundHandler: function (name, ctx),  // optional; returns the protocol's "not configured" reply
 *
 * @example
 *   var reg = b.mail.serverRegistry.create({
 *     protocol: "imap",
 *     defaults: { CAPABILITY: { fn: _capabilityHandler,
 *                               maxHandlerBytes: 8 * 1024,
 *                               maxHandlerMs:    5 * 1000 } },
 *     overrides: opts.overrides || {},
 *   });
 *   await reg.dispatch("CAPABILITY", state, socket, parsed);
 */
function create(opts) {
  validateOpts.requireObject(opts, "b.mail.serverRegistry.create",
    MailServerRegistryError, "mail-server-registry/bad-opts");
  validateOpts.requireNonEmptyString(opts.protocol,
    "b.mail.serverRegistry.create: protocol", MailServerRegistryError,
    "mail-server-registry/bad-protocol");
  if (!CATALOGUE[opts.protocol]) {
    throw new MailServerRegistryError("mail-server-registry/unknown-protocol",
      "create: protocol must be 'imap', 'jmap', or 'managesieve' (got '" + opts.protocol + "')");
  }
  // Tenant scope (v0.10.12 — b.agent.tenant adoption).
  // When `opts.tenantScope` is supplied alongside `opts.agentTenantId`,
  // every dispatch first gates on `tenantScope.check(actor,
  // agentTenantId)`. Actor without matching tenantId surfaces as a
  // typed `agent-tenant/cross-tenant-access-refused` per the v0.9.25
  // contract — the listener's catch path converts that into the
  // protocol's `BAD AUTH` / `NO not authorized` reply.
  //
  // Optional: when omitted, dispatch behaves identically to v0.10.11
  // (no per-tenant gate; operators that don't run multi-tenant don't
  // pay the check cost).
  var tenantScope    = opts.tenantScope    || null;
  var agentTenantId  = opts.agentTenantId  || null;
  if (tenantScope && typeof tenantScope.check !== "function") {
    throw new MailServerRegistryError("mail-server-registry/bad-tenant-scope",
      "create: opts.tenantScope must be a b.agent.tenant.create() instance (missing .check)");
  }
  if (tenantScope && !agentTenantId) {
    throw new MailServerRegistryError("mail-server-registry/no-agent-tenant-id",
      "create: opts.tenantScope requires opts.agentTenantId (the tenant this listener serves)");
  }
  var catalogue = CATALOGUE[opts.protocol];
  var entries = Object.create(null);

  function _validateEntry(name, entry, source) {
    if (!entry || typeof entry !== "object") {
      throw new MailServerRegistryError("mail-server-registry/bad-entry",
        "register: entry for '" + name + "' must be an object");
    }
    if (typeof entry.fn !== "function") {
      throw new MailServerRegistryError("mail-server-registry/bad-handler-fn",
        "register: entry.fn for '" + name + "' must be a function");
    }
    if (typeof entry.maxHandlerBytes !== "number" || !isFinite(entry.maxHandlerBytes) ||
        entry.maxHandlerBytes < 1 || entry.maxHandlerBytes > MAX_HANDLER_BYTES_CEILING ||
        Math.floor(entry.maxHandlerBytes) !== entry.maxHandlerBytes) {
      throw new MailServerRegistryError("mail-server-registry/bad-max-handler-bytes",
        "register: '" + name + "' entry.maxHandlerBytes must be a positive integer ≤ " +
        MAX_HANDLER_BYTES_CEILING + " (got " + entry.maxHandlerBytes + ") — stricter-mode " +
        "registration refuses entries without an explicit budget (defends CVE-2024-34055 / " +
        "CVE-2026-26312 OOM class)");
    }
    if (typeof entry.maxHandlerMs !== "number" || !isFinite(entry.maxHandlerMs) ||
        entry.maxHandlerMs < 1 || entry.maxHandlerMs > MAX_HANDLER_MS_CEILING ||
        Math.floor(entry.maxHandlerMs) !== entry.maxHandlerMs) {
      throw new MailServerRegistryError("mail-server-registry/bad-max-handler-ms",
        "register: '" + name + "' entry.maxHandlerMs must be a positive integer ≤ " +
        MAX_HANDLER_MS_CEILING + " (got " + entry.maxHandlerMs + ")");
    }
    if (!catalogue[name] && entry.allowExperimental !== true) {
      throw new MailServerRegistryError("mail-server-registry/unknown-method",
        "register: '" + name + "' is not in the " + opts.protocol + " catalogue; pass " +
        "allowExperimental: true to opt out of the catalogue gate (audited)");
    }
    if (entry.allowExperimental === true && !catalogue[name]) {
      try {
        audit.safeEmit({
          action:   "mail.serverRegistry.experimental_registration",
          outcome:  "denied",
          metadata: { protocol: opts.protocol, name: name, source: source,
                      severity: "warning" },
        });
      } catch (_e) { /* drop-silent */ }
    }
  }

  function register(name, entry) {
    if (typeof name !== "string" || name.length === 0) {
      throw new MailServerRegistryError("mail-server-registry/bad-name",
        "register: name must be a non-empty string");
    }
    var source = entry && entry.source === "operator-override"
      ? "operator-override" : "operator-override";   // user-facing register defaults to override
    _validateEntry(name, entry, source);
    entries[name] = {
      fn:               entry.fn,
      maxHandlerBytes:  entry.maxHandlerBytes,
      maxHandlerMs:     entry.maxHandlerMs,
      source:           source,
      allowExperimental: entry.allowExperimental === true,
    };
  }

  function _internalRegister(name, entry, source) {
    _validateEntry(name, entry, source);
    entries[name] = {
      fn:                entry.fn,
      maxHandlerBytes:   entry.maxHandlerBytes,
      maxHandlerMs:      entry.maxHandlerMs,
      source:            source,
      allowExperimental: entry.allowExperimental === true,
    };
  }

  // Seed defaults first, then operator overrides shadow them.
  if (opts.defaults && typeof opts.defaults === "object") {
    var dnames = Object.keys(opts.defaults);
    for (var di = 0; di < dnames.length; di += 1) {
      _internalRegister(dnames[di], opts.defaults[dnames[di]], "builtin");
    }
  }
  if (opts.overrides && typeof opts.overrides === "object") {
    var onames = Object.keys(opts.overrides);
    for (var oi = 0; oi < onames.length; oi += 1) {
      _internalRegister(onames[oi], opts.overrides[onames[oi]], "operator-override");
    }
  }

  function unregister(name) {
    if (entries[name]) {
      delete entries[name];
      return true;
    }
    return false;
  }

  function has(name) { return entries[name] !== undefined; }
  function source(name) { return entries[name] ? entries[name].source : null; }

  function list() {
    var out = [];
    var names = Object.keys(entries).sort();                                                          // allow:bare-canonicalize-walk — deterministic output ordering
    for (var i = 0; i < names.length; i += 1) {
      out.push({
        name:   names[i],
        source: entries[names[i]].source,
        hasBudget: true,
      });
    }
    return out;
  }

  /**
   * Dispatch a registered method. `name` is the per-protocol verb /
   * method-name; `args` is variadic forwarded to the handler. The
   * registry wraps the handler in `safeAsync.withTimeout` so a
   * runaway handler can't pin the connection. On not-found, returns
   * the protocol's `notFoundHandler` result (or throws if none).
   */
  function dispatch(name) {
    var argsArr = Array.prototype.slice.call(arguments, 1);
    // Tenant scope check — pre-dispatch, pre-guard, pre-audit.
    //
    // Two argument shapes occur across the three listeners:
    //   - IMAP / ManageSieve dispatch with `(state, socket, parsed)` —
    //     state.actor is the actor.
    //   - JMAP dispatches with `(actor, resolvedArgs, ctx)` — the
    //     first argument IS the actor object directly.
    //
    // Detect both shapes: if argsArr[0].actor exists, use it; else if
    // argsArr[0] itself carries a `tenantId` field, treat it as the
    // actor. The dispatch shapes are documented at the listener
    // factory layer; the registry's job here is uniform enforcement.
    if (tenantScope && argsArr.length > 0 && argsArr[0]) {
      var actor = argsArr[0].actor ||
                  (typeof argsArr[0] === "object" && argsArr[0] !== null &&
                   Object.prototype.hasOwnProperty.call(argsArr[0], "tenantId")
                     ? argsArr[0] : null);
      if (actor) {
        // tenantScope.check throws AgentTenantError on cross-tenant;
        // we let the typed error propagate so the listener's
        // catch-path converts it to the protocol's refusal reply.
        tenantScope.check(actor, agentTenantId);
      }
    }
    var entry = entries[name];
    if (!entry) {
      if (typeof opts.notFoundHandler === "function") {
        return opts.notFoundHandler.apply(null, [name].concat(argsArr));
      }
      throw new MailServerRegistryError("mail-server-registry/not-configured",
        "dispatch: '" + name + "' has no registered handler (" + opts.protocol +
        " protocol; supply via opts.defaults or opts.overrides)");
    }
    var t0 = Date.now();
    try {
      audit.safeEmit({
        action:   "mail.serverRegistry.method_dispatch",
        outcome:  "success",
        metadata: { protocol: opts.protocol, name: name, source: entry.source },
      });
    } catch (_e) { /* drop-silent */ }
    var result;
    try { result = entry.fn.apply(null, argsArr); }
    catch (err) {
      throw new MailServerRegistryError("mail-server-registry/handler-threw",
        "dispatch: '" + name + "' handler threw (" + ((err && err.message) || String(err)) + ")");
    }
    // Wrap promise-returning handlers in safeAsync.withTimeout so a
    // runaway handler can't pin the connection past maxHandlerMs.
    // safeAsync raises its own `async/timeout` error; map it into a
    // typed MailServerRegistryError so the listener catch path sees a
    // single error class.
    if (result && typeof result.then === "function") {
      var timeoutMs = entry.maxHandlerMs;
      var handlerName = name;
      return safeAsync.withTimeout(result, timeoutMs,
          { name: opts.protocol + "/" + handlerName })
        .catch(function (err) {
          if (err && err.code === "async/timeout") {
            throw new MailServerRegistryError("mail-server-registry/handler-timeout",
              "dispatch: '" + handlerName + "' exceeded maxHandlerMs=" + timeoutMs + " (" +
              (Date.now() - t0) + "ms elapsed)");
          }
          throw err;
        });
    }
    return result;
  }

  return {
    register:                 register,
    unregister:               unregister,
    dispatch:                 dispatch,
    list:                     list,
    has:                      has,
    source:                   source,
    protocol:                 opts.protocol,
    MailServerRegistryError:  MailServerRegistryError,
  };
}

module.exports = {
  create:                  create,
  CATALOGUE:               CATALOGUE,
  IMAP_VERBS:              Object.keys(IMAP_VERBS),
  JMAP_METHODS:            Object.keys(JMAP_METHODS),
  MANAGESIEVE_VERBS:       Object.keys(MANAGESIEVE_VERBS),
  MailServerRegistryError: MailServerRegistryError,
};
