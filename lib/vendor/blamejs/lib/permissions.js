"use strict";
/**
 * b.permissions — RBAC primitive.
 *
 *   var perms = b.permissions.create({
 *     roles: {
 *       admin:  { extends: ["editor"], permissions: ["users:delete"] },
 *       editor: ["users:read", "users:write", "posts:*"],
 *       viewer: ["*:read"],
 *     },
 *     audit: b.audit,                  // optional
 *   });
 *
 *   router.delete("/users/:id",
 *     authMiddleware,                  // populates req.user / req.apiKey
 *     perms.require("users:delete"),
 *     deleteUserHandler);
 *
 * The default resolver chain reads the actor from the request:
 *
 *   req.apiKey.scopes  → { scopes: [...] }   (b.apiKey.verify output)
 *   req.user.scopes    → { scopes: [...] }   (operator-set)
 *   req.user.roles     → { roles:  [...] }   (operator-set)
 *
 * Operators with non-default request shapes pass `resolver` to create().
 *
 * Wildcard semantics (b.permissions.match):
 *   "*"             matches any scope (greedy)
 *   "users:*"       matches "users:read", "users:read:detail", etc. (trailing * is greedy)
 *   "*:read"        matches "users:read", "posts:read"
 *   "users:*:read"  matches "users:foo:read" (per-segment *)
 *   "users:read"    matches "users:read" only — no implicit sub-resource grant
 *
 * Validation policy:
 *
 *   - create() role table / scope formats → throw at app init
 *   - require(scope) registration arg     → throw at route declaration
 *   - check(actor, scope) bad actor       → return false (tolerant read)
 *   - resolver returns null in middleware → 401 (missingActorStatus)
 *   - actor lacks scope in middleware     → 403 (denyStatus)
 *   - audit/observability emit failures   → drop silent (hot-path sink)
 *
 * Audit defaults follow the framework's security-defaults stance
 * default: `auditFailures: true`
 * (deny is a security signal), `auditSuccess: false` (per-request noise).
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var safeSql = require("./safe-sql");
var validateOpts = require("./validate-opts");
var { PermissionsError } = require("./framework-error");

var _err = PermissionsError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

// Lowercase tokens, digits, dash, underscore, and `*` allowed per
// segment. Scope format is segments separated by `:`.
var SCOPE_RE = /^[a-z0-9_*-]+(:[a-z0-9_*-]+)*$/;
// Bound the regex engine on operator-supplied scope strings. 256 chars
// holds any realistic real-world scope (typical scopes run 8-32 chars);
// rejecting longer keeps the regex linear regardless of input shape.
var SCOPE_MAX_LENGTH = C.BYTES.bytes(256);

// Audit defaults: BOTH success and failure default ON for permissions.
// Unlike api-key.verify (which is gate-keeping for a downstream action
// the application separately audits), a permissions.check IS the
// authorization decision — there's no further-downstream audit event.
// "user X granted users:delete at time T" is exactly what compliance
// auditors ask for. Operators with extreme volume opt out via
// auditSuccess: false; failures remain on regardless.
var DEFAULTS = Object.freeze({
  auditFailures:       true,
  auditSuccess:        true,
  denyStatus:          403,
  missingActorStatus:  401,
});

// ---- Wildcard matcher ----

function match(granted, required) {
  if (typeof granted !== "string" || typeof required !== "string") return false;
  if (granted.length === 0 || required.length === 0) return false;
  var gParts = granted.split(":");
  var rParts = required.split(":");
  for (var i = 0; i < gParts.length; i++) {
    var g = gParts[i];
    if (g === "*") {
      // Trailing * is greedy — matches the rest of required.
      if (i === gParts.length - 1) return true;
      // Per-segment * — matches THIS segment of required (any value),
      // continue to next segment. Required must have a segment here.
      if (i >= rParts.length) return false;
      continue;
    }
    if (i >= rParts.length) return false;     // granted is more specific than required
    if (g !== rParts[i]) return false;
  }
  // Reached end of granted without wildcard. Lengths must match exactly
  // (no implicit sub-resource grant).
  return rParts.length === gParts.length;
}

// ---- Role table validation + expansion ----

function _validateScopePattern(scope, ctx) {
  if (typeof scope !== "string" || scope.length === 0) {
    throw _err("BAD_SCOPE", ctx + ": scope must be a non-empty string, got " + typeof scope);
  }
  // Length cap before the regex test — bound the engine on hostile
  // input lengths even though SCOPE_RE is anchored.
  if (scope.length > SCOPE_MAX_LENGTH || !SCOPE_RE.test(scope)) {
    throw _err("BAD_SCOPE", ctx + ": scope '" + scope +
      "' is empty, too long, or doesn't match " + SCOPE_RE +
      " (lowercase tokens with optional `*`)");
  }
}

function _normalizeRoleEntry(name, entry) {
  if (Array.isArray(entry)) {
    return { extends: [], permissions: entry.slice(), dbRole: null,
      requireMfa: false, mfaWindowMs: null };
  }
  if (entry && typeof entry === "object") {
    var ext = entry.extends || [];
    var perms = entry.permissions || [];
    if (!Array.isArray(ext)) {
      throw _err("BAD_ROLE", "role '" + name + "': extends must be an array of role names");
    }
    if (!Array.isArray(perms)) {
      throw _err("BAD_ROLE", "role '" + name + "': permissions must be an array of scope strings");
    }
    var dbRole = null;
    if (entry.dbRole !== undefined && entry.dbRole !== null) {
      if (typeof entry.dbRole !== "string" || entry.dbRole.length === 0) {
        throw _err("BAD_ROLE",
          "role '" + name + "': dbRole must be a non-empty string");
      }
      // dbRole feeds straight into externalDb backend pick + the
      // dbRoleFor middleware's identifier check; validate at create()
      // time so a typo surfaces at boot, not on the first request.
      try {
        safeSql.validateIdentifier(entry.dbRole, { allowReserved: false });
      } catch (e) {
        throw _err("BAD_ROLE",
          "role '" + name + "': dbRole '" + entry.dbRole +
          "' is not a valid SQL identifier: " + ((e && e.message) || String(e)));
      }
      dbRole = entry.dbRole;
    }
    var requireMfa = entry.requireMfa === true;
    var mfaWindowMs = null;
    if (entry.mfaWindowMs !== undefined && entry.mfaWindowMs !== null) {
      if (typeof entry.mfaWindowMs !== "number" || !isFinite(entry.mfaWindowMs) || entry.mfaWindowMs <= 0) {
        throw _err("BAD_ROLE",
          "role '" + name + "': mfaWindowMs must be a positive finite number");
      }
      mfaWindowMs = entry.mfaWindowMs;
    }
    return { extends: ext.slice(), permissions: perms.slice(), dbRole: dbRole,
      requireMfa: requireMfa, mfaWindowMs: mfaWindowMs };
  }
  throw _err("BAD_ROLE", "role '" + name + "' must be an array of scopes or { extends?, permissions, dbRole?, requireMfa?, mfaWindowMs? }");
}

function _validateRoles(roles) {
  if (!roles || typeof roles !== "object" || Array.isArray(roles)) {
    throw _err("BAD_OPT", "permissions.create: roles must be an object map of name → spec");
  }
  var names = Object.keys(roles);
  if (names.length === 0) {
    throw _err("BAD_OPT", "permissions.create: roles map must have at least one role");
  }
  var normalized = {};
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (typeof name !== "string" || name.length === 0) {
      throw _err("BAD_ROLE", "role name must be a non-empty string");
    }
    var spec = _normalizeRoleEntry(name, roles[name]);
    for (var j = 0; j < spec.permissions.length; j++) {
      _validateScopePattern(spec.permissions[j], "role '" + name + "'");
    }
    for (var k = 0; k < spec.extends.length; k++) {
      if (typeof spec.extends[k] !== "string" || spec.extends[k].length === 0) {
        throw _err("BAD_ROLE", "role '" + name + "': extends entry must be a non-empty string");
      }
    }
    normalized[name] = spec;
  }
  // Check extends references resolve to known roles
  for (var n = 0; n < names.length; n++) {
    var spec2 = normalized[names[n]];
    for (var m = 0; m < spec2.extends.length; m++) {
      if (!Object.prototype.hasOwnProperty.call(normalized, spec2.extends[m])) {
        throw _err("UNKNOWN_ROLE", "role '" + names[n] + "': extends references unknown role '" +
          spec2.extends[m] + "'");
      }
    }
  }
  // Cycle detection via DFS
  for (var p = 0; p < names.length; p++) {
    _detectCycle(names[p], normalized, []);
  }
  return normalized;
}

function _detectCycle(roleName, table, stack) {
  if (stack.indexOf(roleName) !== -1) {
    throw _err("CYCLE", "permissions.create: cycle in extends chain: " +
      stack.concat([roleName]).join(" → "));
  }
  var spec = table[roleName];
  for (var i = 0; i < spec.extends.length; i++) {
    _detectCycle(spec.extends[i], table, stack.concat([roleName]));
  }
}

function _expandOne(roleName, table, visited, out) {
  if (visited.has(roleName)) return;
  visited.add(roleName);
  var spec = table[roleName];
  if (!spec) return;
  for (var i = 0; i < spec.extends.length; i++) {
    _expandOne(spec.extends[i], table, visited, out);
  }
  for (var j = 0; j < spec.permissions.length; j++) {
    if (out.indexOf(spec.permissions[j]) === -1) out.push(spec.permissions[j]);
  }
}

// ---- Default resolver ----

function _defaultResolver(req) {
  if (!req || typeof req !== "object") return null;
  if (req.apiKey && Array.isArray(req.apiKey.scopes)) return { scopes: req.apiKey.scopes };
  if (req.user && Array.isArray(req.user.scopes))     return { scopes: req.user.scopes };
  if (req.user && Array.isArray(req.user.roles))      return { roles:  req.user.roles };
  return null;
}

// ---- Validation: create opts ----

function _validateCreateOpts(opts) {
  validateOpts.requireObject(opts, "permissions.create", PermissionsError);
  validateOpts.optionalFunction(opts.resolver, "permissions.create: resolver", PermissionsError);
  validateOpts.auditShape(opts.audit, "permissions.create", PermissionsError);
  validateOpts.optionalBoolean(opts.auditFailures, "permissions.create: auditFailures", PermissionsError);
  validateOpts.optionalBoolean(opts.auditSuccess, "permissions.create: auditSuccess", PermissionsError);
  if (opts.denyStatus !== undefined &&
      (typeof opts.denyStatus !== "number" || !isFinite(opts.denyStatus) || opts.denyStatus < 100 || opts.denyStatus > 599)) {
    throw _err("BAD_OPT", "permissions.create: denyStatus must be an HTTP status code (100-599)");
  }
  if (opts.missingActorStatus !== undefined &&
      (typeof opts.missingActorStatus !== "number" || !isFinite(opts.missingActorStatus) ||
       opts.missingActorStatus < 100 || opts.missingActorStatus > 599)) {
    throw _err("BAD_OPT", "permissions.create: missingActorStatus must be an HTTP status code (100-599)");
  }
  validateOpts.optionalFunction(opts.responder, "permissions.create: responder", PermissionsError);
}

// ---- Registry ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "roles", "resolver", "audit", "auditFailures", "auditSuccess",
    "denyStatus", "missingActorStatus", "responder",
  ], "permissions");
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var roleTable = _validateRoles(opts.roles);
  var resolver  = opts.resolver || _defaultResolver;
  var audit     = opts.audit || null;
  var auditFailures = cfg.auditFailures;
  var auditSuccess  = cfg.auditSuccess;
  var denyStatus    = cfg.denyStatus;
  var missingActorStatus = cfg.missingActorStatus;
  var responder = opts.responder || _defaultResponder;

  // ABAC predicate registry. Each entry: scope-string → async predicate
  // function (actor, context) → boolean. The middleware evaluates the
  // predicate AFTER the RBAC scope check passes — so a route protected
  // by `perms.require("orders.read")` first checks the actor has the
  // orders:read scope, then (if the scope has a policy registered)
  // evaluates the predicate with the actor + a per-request context
  // built by the route's `context` middleware opt. ABAC + RBAC stack
  // — a route needs to pass BOTH layers when both are configured.
  var policies = {};

  function policy(scope, predicate) {
    _validateScopePattern(scope, "permissions.policy");
    if (typeof predicate !== "function") {
      throw _err("BAD_OPT", "permissions.policy: predicate must be a function (actor, context) -> bool");
    }
    if (policies[scope]) {
      throw _err("DUPLICATE_POLICY", "permissions.policy: '" + scope + "' is already registered");
    }
    policies[scope] = predicate;
  }

  function _findPolicy(requestedScope) {
    // Exact match wins; no wildcard expansion (a wildcard policy
    // gating arbitrary scopes is too easy to misconfigure).
    return policies[requestedScope] || null;
  }

  var _emitRaw = validateOpts.makeAuditEmitter(audit);
  function _auditEmit(action, info) {
    if (info && info.outcome === "success" && !auditSuccess) return;
    if (info && info.outcome !== "success" && !auditFailures) return;
    _emitRaw(action, info);
  }

  function expand(roleNames) {
    if (!Array.isArray(roleNames)) return [];
    var visited = new Set();
    var out = [];
    for (var i = 0; i < roleNames.length; i++) {
      if (typeof roleNames[i] === "string" && Object.prototype.hasOwnProperty.call(roleTable, roleNames[i])) {
        _expandOne(roleNames[i], roleTable, visited, out);
      }
    }
    return out;
  }

  function _actorScopes(actor) {
    if (!actor || typeof actor !== "object") return [];
    if (Array.isArray(actor.scopes)) return actor.scopes;
    if (Array.isArray(actor.roles))  return expand(actor.roles);
    return [];
  }

  function check(actor, requiredScope) {
    var scopes = _actorScopes(actor);
    for (var i = 0; i < scopes.length; i++) {
      if (typeof scopes[i] === "string" && match(scopes[i], requiredScope)) return true;
    }
    return false;
  }

  function checkAll(actor, requiredScopes) {
    if (!Array.isArray(requiredScopes)) return false;
    for (var i = 0; i < requiredScopes.length; i++) {
      if (!check(actor, requiredScopes[i])) return false;
    }
    return requiredScopes.length > 0;
  }

  function checkAny(actor, requiredScopes) {
    if (!Array.isArray(requiredScopes)) return false;
    for (var i = 0; i < requiredScopes.length; i++) {
      if (check(actor, requiredScopes[i])) return true;
    }
    return false;
  }

  // Middleware factory. `mode` is "single" | "all" | "any"; `requested`
  // is the scope or scope list. Throw at registration time on bad shape.
  function _middleware(mode, requested, mwOpts) {
    if (mode === "single") {
      _validateScopePattern(requested, "permissions.require");
    } else {
      if (!Array.isArray(requested) || requested.length === 0) {
        throw _err("BAD_OPT", "permissions." + (mode === "all" ? "requireAll" : "requireAny") +
          ": scopes must be a non-empty array");
      }
      for (var i = 0; i < requested.length; i++) {
        _validateScopePattern(requested[i], "permissions." + (mode === "all" ? "requireAll" : "requireAny"));
      }
    }

    // Per-route MFA enforcement opts: { requireMfa, mfaWindowMs }.
    // When set, the middleware blocks unless the actor's mfaAuthenticated
    // flag is truthy AND (when mfaWindowMs is set) actor.mfaAt is fresher
    // than (now - mfaWindowMs). The actor signal is operator-set: after
    // a successful TOTP / passkey step-up, the route handler stamps
    // req.user.mfaAuthenticated = true and req.user.mfaAt = Date.now().
    mwOpts = mwOpts || {};
    var routeRequireMfa  = mwOpts.requireMfa === true;
    var routeMfaWindowMs = null;
    if (mwOpts.mfaWindowMs !== undefined && mwOpts.mfaWindowMs !== null) {
      if (typeof mwOpts.mfaWindowMs !== "number" || !isFinite(mwOpts.mfaWindowMs) || mwOpts.mfaWindowMs <= 0) {
        throw _err("BAD_OPT", "permissions middleware: mfaWindowMs must be a positive finite number");
      }
      routeMfaWindowMs = mwOpts.mfaWindowMs;
    }
    // ABAC context provider — operator-supplied function (req)→object.
    // The function runs once per request, AFTER scope/MFA pass, BEFORE
    // the policy predicate. Whatever it returns is passed to the
    // policy as `context`. Async functions are awaited.
    var contextProvider = mwOpts.context;
    if (contextProvider !== undefined && typeof contextProvider !== "function") {
      throw _err("BAD_OPT", "permissions middleware: context must be a function (req) -> object");
    }

    return async function permissionsMiddleware(req, res, next) {
      var actor = resolver(req);
      if (!actor) {
        // Diagnostic: the most common cause of a null actor is that
        // attachUser/auth wasn't mounted before this middleware, so
        // req.user / req.apiKey are still undefined. Emit a hint —
        // operators tracing a 401 here see exactly what to check first.
        var hint = (req && (req.user || req.apiKey))
          ? "actor present on req but resolver returned null — check resolver implementation"
          : "no req.user or req.apiKey — confirm attachUser / apiKey-verify middleware is mounted before perms.require()";
        _emitEvent("permissions.missing_actor", 1,
          { requested: _labelize(requested) });
        _auditEmit("permissions.missing_actor", {
          actor:    _actorAuditShape(null, req),
          resource: { kind: "permission", id: _labelize(requested) },
          outcome:  "failure",
          reason:   "no-actor",
          metadata: { hint: hint },
        });
        return responder(req, res, missingActorStatus, {
          error:  "missing_actor",
          status: missingActorStatus,
        });
      }

      var ok;
      if (mode === "single")  ok = check(actor, requested);
      else if (mode === "all") ok = checkAll(actor, requested);
      else                     ok = checkAny(actor, requested);

      if (!ok) {
        _emitEvent("permissions.check", 1,
          { outcome: "deny", requested: _labelize(requested), mode: mode });
        _auditEmit("permissions.check.deny", {
          actor:    _actorAuditShape(actor, req),
          resource: { kind: "permission", id: _labelize(requested) },
          outcome:  "failure",
          reason:   "forbidden",
          metadata: { mode: mode },
        });
        return responder(req, res, denyStatus, {
          error:     "forbidden",
          status:    denyStatus,
          requested: _labelize(requested),
        });
      }

      // MFA enforcement gate. Two sources of "this needs MFA":
      //   1. Per-route opt: perms.require("scope", { requireMfa: true })
      //   2. Per-role flag: a role spec with requireMfa:true that
      //      contributes to satisfying the requested scope
      // Either source enabling MFA forces the gate. mfaWindowMs (per-route
      // OR per-role, route wins on conflict) bounds freshness — without
      // it, ANY past MFA stamp counts (which is too permissive for high-
      // value routes; operators set a window like C.TIME.minutes(15)).
      var enforceMfa = routeRequireMfa;
      var enforceWindowMs = routeMfaWindowMs;
      if (!enforceMfa) {
        // Walk the actor's roles and check whether any role with
        // requireMfa=true contributes a permission that matches the
        // requested scope. If so, MFA is required regardless of the
        // route-level opt.
        var actorRoles = Array.isArray(actor.roles) ? actor.roles : [];
        for (var ri = 0; ri < actorRoles.length; ri++) {
          var rname = actorRoles[ri];
          if (typeof rname !== "string") continue;
          var rspec = roleTable[rname];
          if (!rspec || !rspec.requireMfa) continue;
          // Cheap match: if the role grants any scope that satisfies the
          // requested scope (single mode) or any of the requested
          // (all/any modes), MFA is required for this route.
          var visited = new Set();
          var roleScopes = [];
          _expandOne(rname, roleTable, visited, roleScopes);
          var roleMatches = false;
          var requestedList = mode === "single" ? [requested] : requested;
          outer: for (var rj = 0; rj < roleScopes.length; rj++) {
            for (var rk = 0; rk < requestedList.length; rk++) {
              if (match(roleScopes[rj], requestedList[rk])) {
                roleMatches = true; break outer;
              }
            }
          }
          if (roleMatches) {
            enforceMfa = true;
            if (enforceWindowMs === null && rspec.mfaWindowMs !== null) {
              enforceWindowMs = rspec.mfaWindowMs;
            }
          }
        }
      }

      if (enforceMfa) {
        // Window floor — when neither route nor role supplies an
        // explicit mfaWindowMs, default to 15 minutes. Without this
        // floor, a stolen long-lived cookie carrying an old `mfaAt`
        // walks past every requireMfa: true gate. Operators who want
        // an explicit no-window pass-through must say so via
        // mfaWindowMs: Infinity (audited reason).
        if (enforceWindowMs === null) {
          enforceWindowMs = C.TIME.minutes(15);
        }
        var mfaOk = actor.mfaAuthenticated === true;
        if (mfaOk && enforceWindowMs !== null && enforceWindowMs !== Infinity) {
          var mfaAt = typeof actor.mfaAt === "number" ? actor.mfaAt : 0;
          if (Date.now() - mfaAt > enforceWindowMs) {
            mfaOk = false;
          }
        }
        if (!mfaOk) {
          _emitEvent("permissions.mfa_required", 1,
            { requested: _labelize(requested), mode: mode });
          _auditEmit("permissions.mfa.required", {
            actor:    _actorAuditShape(actor, req),
            resource: { kind: "permission", id: _labelize(requested) },
            outcome:  "denied",
            reason:   "mfa-required",
            metadata: { mode: mode, windowMs: enforceWindowMs },
          });
          return responder(req, res, denyStatus, {
            error:     "mfa_required",
            status:    denyStatus,
            requested: _labelize(requested),
          });
        }
      }

      // ABAC layer fires for every requested scope that has a
      // registered policy predicate. Single-mode evaluates the one
      // scope; requireAll evaluates each scope's policy (every must
      // pass); requireAny evaluates only the policies on scopes the
      // actor's RBAC layer satisfied (so a failing policy on a scope
      // the actor doesn't even hold doesn't leak the policy's
      // existence). Each predicate failure short-circuits with a
      // policy.deny audit row naming the failing scope.
      var policyTargets = [];
      if (mode === "single" && _findPolicy(requested)) {
        policyTargets.push(requested);
      } else if (mode === "all" || mode === "any") {
        for (var pi = 0; pi < requested.length; pi++) {
          if (_findPolicy(requested[pi])) {
            if (mode === "any" && !check(actor, requested[pi])) continue;
            policyTargets.push(requested[pi]);
          }
        }
      }
      if (policyTargets.length > 0) {
        var policyContext = null;
        if (contextProvider) {
          try {
            policyContext = await contextProvider(req);
          } catch (e) {
            _emitEvent("permissions.policy_context_error", 1,
              { requested: _labelize(requested) });
            _auditEmit("permissions.policy.error", {
              actor:    _actorAuditShape(actor, req),
              resource: { kind: "permission", id: _labelize(requested) },
              outcome:  "failure",
              reason:   "context-provider-threw",
              metadata: { error: (e && e.message) || String(e), mode: mode },
            });
            return responder(req, res, denyStatus, {
              error:     "policy_context_error",
              status:    denyStatus,
              requested: _labelize(requested),
            });
          }
        }
        for (var pti = 0; pti < policyTargets.length; pti++) {
          var thisScope = policyTargets[pti];
          var pred = _findPolicy(thisScope);
          var verdict;
          try {
            verdict = await pred(actor, policyContext);
          } catch (e2) {
            _emitEvent("permissions.policy_error", 1, { requested: thisScope });
            _auditEmit("permissions.policy.error", {
              actor:    _actorAuditShape(actor, req),
              resource: { kind: "permission", id: thisScope },
              outcome:  "failure",
              reason:   "predicate-threw",
              metadata: { error: (e2 && e2.message) || String(e2), mode: mode },
            });
            return responder(req, res, denyStatus, {
              error:     "policy_error",
              status:    denyStatus,
              requested: thisScope,
            });
          }
          if (verdict !== true) {
            _emitEvent("permissions.policy_denied", 1, { requested: thisScope });
            _auditEmit("permissions.policy.deny", {
              actor:    _actorAuditShape(actor, req),
              resource: { kind: "permission", id: thisScope },
              outcome:  "failure",
              reason:   "policy-predicate-returned-falsy",
              metadata: { mode: mode, scopeIndex: pti },
            });
            return responder(req, res, denyStatus, {
              error:     "policy_denied",
              status:    denyStatus,
              requested: thisScope,
            });
          }
        }
      }

      _emitEvent("permissions.check", 1,
        { outcome: "success", mode: mode });
      _auditEmit("permissions.check.success", {
        actor:    _actorAuditShape(actor, req),
        resource: { kind: "permission", id: _labelize(requested) },
        outcome:  "success",
        metadata: { mode: mode, mfaEnforced: enforceMfa },
      });
      next();
    };
  }

  // dbRoleFor — walk the actor's roles in order and return the first
  // declared dbRole. Composes with b.middleware.dbRoleFor so a single
  // RBAC table drives both authorization scopes and request-time DB
  // role binding.
  //
  // The arg can be the request (default resolver pulls actor from
  // req.user / req.apiKey) OR an actor object directly. Returns null if
  // no actor is found OR the actor's roles don't include any with a
  // declared dbRole.
  //
  // Lookup order: extends are walked depth-first so a child role that
  // overrides dbRole takes precedence over its parent. When multiple
  // top-level roles are listed, the first wins (operators wanting a
  // priority order should list more-specific roles first).
  function dbRoleFor(reqOrActor) {
    var actor = reqOrActor;
    // Heuristic: a request shape carries headers / url; resolve through
    // the configured resolver. An actor shape has roles / scopes
    // directly.
    if (actor && (actor.headers || actor.url || actor.method)) {
      actor = resolver(actor);
    }
    if (!actor || typeof actor !== "object") return null;
    var roleNames = Array.isArray(actor.roles) ? actor.roles : null;
    if (!roleNames || roleNames.length === 0) return null;
    // Walk the same DFS order expand() uses so the first-seen dbRole
    // is consistent with how scopes are inherited.
    var visited = new Set();
    for (var i = 0; i < roleNames.length; i++) {
      var name = roleNames[i];
      if (typeof name !== "string") continue;
      if (!Object.prototype.hasOwnProperty.call(roleTable, name)) continue;
      var found = _findDbRole(name, roleTable, visited);
      if (found) return found;
    }
    return null;
  }

  return {
    require:    function (scope, mwOpts)  { return _middleware("single", scope,  mwOpts); },
    requireAll: function (scopes, mwOpts) { return _middleware("all",    scopes, mwOpts); },
    requireAny: function (scopes, mwOpts) { return _middleware("any",    scopes, mwOpts); },
    policy:     policy,
    check:      check,
    checkAll:   checkAll,
    checkAny:   checkAny,
    expand:     expand,
    dbRoleFor:  dbRoleFor,
    has:        function (name) { return Object.prototype.hasOwnProperty.call(roleTable, name); },
    roles:      Object.freeze(Object.keys(roleTable)),
  };
}

function _findDbRole(roleName, table, visited) {
  if (visited.has(roleName)) return null;
  visited.add(roleName);
  var spec = table[roleName];
  if (!spec) return null;
  // Child overrides parent — check this role's own dbRole first, then
  // recurse into extends.
  if (spec.dbRole) return spec.dbRole;
  for (var i = 0; i < spec.extends.length; i++) {
    var found = _findDbRole(spec.extends[i], table, visited);
    if (found) return found;
  }
  return null;
}

// ---- Helpers ----

function _labelize(requested) {
  return Array.isArray(requested) ? requested.join(",") : String(requested);
}

function _actorAuditShape(actor, req) {
  // Pull the 5 W's (WHO/WHERE/HOW) from the request, then layer the
  // resolver-supplied actor identity on top so userId/roles/scopes
  // aren't lost when the request itself doesn't carry them.
  var base = requestHelpers.extractActorContext(req);
  if (actor) {
    if (actor.userId)               base.userId = actor.userId;
    if (Array.isArray(actor.roles)) base.roles  = actor.roles.slice();
    if (Array.isArray(actor.scopes)) base.scopes = actor.scopes.slice();
  }
  return base;
}

function _defaultResponder(req, res, status, info) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(info));
}

module.exports = {
  create:           create,
  match:            match,
  PermissionsError: PermissionsError,
  DEFAULTS:         DEFAULTS,
};
