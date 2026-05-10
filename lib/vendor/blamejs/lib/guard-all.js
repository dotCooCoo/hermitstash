"use strict";
/**
 * @module b.guardAll
 * @featured true
 * @nav    Guards
 * @title  Guard All
 *
 * @intro
 *   Aggregate gate that dispatches to every registered b.guard* member
 *   by KIND. Content guards (csv / html / svg / archive / json / yaml /
 *   xml / markdown / email) route by MIME type or file extension;
 *   standalone guards (filename / domain / uuid / cidr / time / mime /
 *   jwt / oauth / graphql / shell / regex / jsonpath / template /
 *   image / pdf / auth) operate on non-content axes and surface via
 *   `allGuards()` for the adaptive integration harness.
 *
 *   The framework thesis applied to content safety: every shipped
 *   guard is ON by default; operators opt OUT explicitly with an
 *   audited `reason` per guard. New guards added in future slices
 *   auto-register through GUARDS / STANDALONE_GUARDS and operators
 *   inherit the new coverage without re-wiring.
 *
 *   Registry contract — every primitive registered into guard-all
 *   MUST export NAME / MIME_TYPES / EXTENSIONS (content guards only) /
 *   PROFILES (must include strict / balanced / permissive) /
 *   COMPLIANCE_POSTURES (must include hipaa / pci-dss / gdpr / soc2) /
 *   gate(opts). A parity check at module load throws GuardAllError if
 *   any member drifts from the contract — that's the registry gate
 *   that keeps every future guard slice conformant.
 *
 *   Per-guard extension profiles (e.g. csv's "email-attachment") are
 *   reached via the `override` map; the aggregator's `profile` opt
 *   only takes the shared vocabulary so one string applies cleanly
 *   across every member.
 *
 * @card
 *   Aggregate gate that dispatches to every registered b.guard* member by KIND.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var gateContract = require("./gate-contract");
var { GuardAllError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardAllError.factory;

// Registered guards. Ordering is the order they get walked by list();
// dispatch via gateContract.contentTypeMux is O(1) regardless.
var GUARDS = [
  require("./guard-csv"),
  require("./guard-html"),
  require("./guard-svg"),
  require("./guard-archive"),
  require("./guard-json"),
  require("./guard-yaml"),
  require("./guard-xml"),
  require("./guard-markdown"),
  require("./guard-email"),
];

// STANDALONE_GUARDS — guard-* primitives that don't fit content-type
// routing. They participate in the family (NAME / KIND / INTEGRATION_
// FIXTURES exports + shared profiles + postures) but operate on a
// non-content axis (filename string, future identifier types). The
// adaptive integration harness iterates `allGuards()` to pick them up.
var STANDALONE_GUARDS = [
  require("./guard-filename"),
  require("./guard-domain"),
  require("./guard-uuid"),
  require("./guard-cidr"),
  require("./guard-time"),
  require("./guard-mime"),
  require("./guard-jwt"),
  require("./guard-oauth"),
  require("./guard-graphql"),
  require("./guard-shell"),
  require("./guard-regex"),
  require("./guard-jsonpath"),
  require("./guard-template"),
  require("./guard-image"),
  require("./guard-pdf"),
  require("./guard-auth"),
];

// Framework-wide profile + posture vocabulary that every guard MUST
// support. Adding a new shared profile / posture is a coordinated
// cross-guard change — every member must implement it.
var SHARED_PROFILES = Object.freeze(["strict", "balanced", "permissive"]);
var SHARED_POSTURES = Object.freeze(["hipaa", "pci-dss", "gdpr", "soc2"]);

// ---- Registry parity check (runs at module load) ----

function _verifyParity() {
  var failures = [];
  // Walk both registries — content guards (with MIME_TYPES + EXTENSIONS)
  // and standalone guards (filename / domain / uuid / cidr / time /
  // mime / jwt / oauth / graphql / shell / regex / jsonpath / template /
  // image / pdf / auth). Standalone guards skip the MIME/EXTENSION
  // checks but every guard MUST declare the shared profile + posture
  // vocabulary so b.guardAll.allGuards() returns a uniform surface.
  var allGuards = GUARDS.concat(STANDALONE_GUARDS);
  for (var i = 0; i < allGuards.length; i += 1) {
    var g = allGuards[i];
    var isContent = i < GUARDS.length;
    if (!g || typeof g !== "object") {
      failures.push("guard at index " + i + " is not an exported module object");
      continue;
    }
    if (typeof g.NAME !== "string" || g.NAME.length === 0) {
      failures.push("guard at index " + i + ": missing NAME export");
      continue;
    }
    if (isContent) {
      if (!Array.isArray(g.MIME_TYPES) || g.MIME_TYPES.length === 0) {
        failures.push(g.NAME + ": missing or empty MIME_TYPES export");
      }
      if (!Array.isArray(g.EXTENSIONS) || g.EXTENSIONS.length === 0) {
        failures.push(g.NAME + ": missing or empty EXTENSIONS export");
      }
    }
    if (typeof g.gate !== "function") {
      failures.push(g.NAME + ": missing gate(opts) function");
    }
    SHARED_PROFILES.forEach(function (p) {
      if (!g.PROFILES || !g.PROFILES[p]) {
        failures.push(g.NAME + ": does not declare shared profile " + JSON.stringify(p));
      }
    });
    SHARED_POSTURES.forEach(function (p) {
      if (!g.COMPLIANCE_POSTURES || !g.COMPLIANCE_POSTURES[p]) {
        failures.push(g.NAME + ": does not declare shared compliance posture " + JSON.stringify(p));
      }
    });
  }
  // Detect duplicate NAMEs across the full registry (both content +
  // standalone) so a future guard with a NAME collision surfaces at
  // boot instead of silently overriding _byName lookups. MIME / EXT
  // collision detection stays scoped to content guards (standalone
  // guards have no MIME/EXTENSIONS).
  var nameSeen = Object.create(null);
  var mimeSeen = Object.create(null);
  var extSeen  = Object.create(null);
  for (var j = 0; j < allGuards.length; j += 1) {
    var gg = allGuards[j];
    if (gg && gg.NAME) {
      if (nameSeen[gg.NAME]) failures.push("duplicate NAME " + JSON.stringify(gg.NAME) +
                                            " across the full guard registry");
      nameSeen[gg.NAME] = true;
    }
  }
  for (var jc = 0; jc < GUARDS.length; jc += 1) {
    var ggc = GUARDS[jc];
    if (ggc && Array.isArray(ggc.MIME_TYPES)) {
      ggc.MIME_TYPES.forEach(function (m) {
        var k = String(m).toLowerCase();
        if (mimeSeen[k]) failures.push("duplicate MIME_TYPE " + JSON.stringify(k) +
                                       " across multiple guards");
        mimeSeen[k] = true;
      });
    }
    if (ggc && Array.isArray(ggc.EXTENSIONS)) {
      ggc.EXTENSIONS.forEach(function (e) {
        var k = String(e).toLowerCase();
        if (extSeen[k]) failures.push("duplicate EXTENSION " + JSON.stringify(k) +
                                      " across multiple guards");
        extSeen[k] = true;
      });
    }
  }
  if (failures.length) {
    throw _err("guard-all/parity-fail",
      "guardAll registry parity check failed:\n  " + failures.join("\n  "));
  }
}
_verifyParity();

// ---- Internal helpers ----

function _byName(name) {
  for (var i = 0; i < GUARDS.length; i += 1) {
    if (GUARDS[i].NAME === name) return GUARDS[i];
  }
  return null;
}

function _validateExceptFor(exceptFor) {
  if (exceptFor == null) return {};
  validateOpts.optionalPlainObject(exceptFor,
    "guardAll: exceptFor", GuardAllError, "guard-all/bad-opt",
    "must be a plain object keyed by guard NAME");
  var keys = Object.keys(exceptFor);
  for (var i = 0; i < keys.length; i += 1) {
    var name = keys[i];
    if (!_byName(name)) {
      throw _err("guard-all/unknown-guard",
        "exceptFor refers to unknown guard " + JSON.stringify(name) +
        "; registered: " + GUARDS.map(function (g) { return g.NAME; }).join(", "));
    }
    var entry = exceptFor[name];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw _err("guard-all/bad-opt",
        "exceptFor[" + JSON.stringify(name) + "] must be a plain object " +
        "with a non-empty reason string");
    }
    if (typeof entry.reason !== "string" || entry.reason.trim().length === 0) {
      throw _err("guard-all/missing-reason",
        "exceptFor[" + JSON.stringify(name) + "] requires a non-empty " +
        "reason string — opting a guard out is auditable");
    }
  }
  return exceptFor;
}

function _validateOverride(override) {
  if (override == null) return {};
  validateOpts.optionalPlainObject(override,
    "guardAll: override", GuardAllError, "guard-all/bad-opt",
    "must be a plain object keyed by guard NAME");
  var keys = Object.keys(override);
  for (var i = 0; i < keys.length; i += 1) {
    var name = keys[i];
    if (!_byName(name)) {
      throw _err("guard-all/unknown-guard",
        "override refers to unknown guard " + JSON.stringify(name));
    }
    var entry = override[name];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw _err("guard-all/bad-opt",
        "override[" + JSON.stringify(name) + "] must be a plain object " +
        "of opts to merge into the guard's gate(opts)");
    }
  }
  return override;
}

function _validateProfileAndPosture(opts) {
  if (opts.profile != null) {
    if (typeof opts.profile !== "string") {
      throw _err("guard-all/bad-opt",
        "profile must be a string; got " + typeof opts.profile);
    }
    if (SHARED_PROFILES.indexOf(opts.profile) === -1) {
      throw _err("guard-all/bad-profile",
        "profile " + JSON.stringify(opts.profile) +
        " is not in the shared vocabulary; allowed: " +
        SHARED_PROFILES.join(", ") +
        ". Per-guard extension profiles (e.g. csv's email-attachment) " +
        "are reachable via the override map.");
    }
  }
  if (opts.compliancePosture != null) {
    if (typeof opts.compliancePosture !== "string") {
      throw _err("guard-all/bad-opt",
        "compliancePosture must be a string; got " + typeof opts.compliancePosture);
    }
    if (SHARED_POSTURES.indexOf(opts.compliancePosture) === -1) {
      throw _err("guard-all/bad-posture",
        "compliancePosture " + JSON.stringify(opts.compliancePosture) +
        " is not in the shared vocabulary; allowed: " + SHARED_POSTURES.join(", "));
    }
  }
}

// _resolveActiveGuards — returns the set of (guard, mergedOpts) pairs
// that are NOT in exceptFor. Each entry's opts are the base opts +
// override entry merged in.
function _resolveActiveGuards(opts) {
  var exceptFor = _validateExceptFor(opts.exceptFor);
  var override  = _validateOverride(opts.override);
  _validateProfileAndPosture(opts);

  var baseOpts = {
    profile:               opts.profile,
    compliancePosture:     opts.compliancePosture,
    mode:                  opts.mode,
    audit:                 opts.audit,
    observability:         opts.observability,
    forensicEvidenceStore: opts.forensicEvidenceStore,
    forensicSnippetBytes:  opts.forensicSnippetBytes,
    cache:                 opts.cache,
    cacheTtlMs:            opts.cacheTtlMs,
    maxRuntimeMs:          opts.maxRuntimeMs,
    beforeCheck:           opts.beforeCheck,
    afterCheck:            opts.afterCheck,
    onIssue:               opts.onIssue,
    onSanitize:            opts.onSanitize,
    onRefuse:              opts.onRefuse,
    onAudit:               opts.onAudit,
  };

  var active = [];
  var skipped = [];
  for (var i = 0; i < GUARDS.length; i += 1) {
    var g = GUARDS[i];
    if (Object.prototype.hasOwnProperty.call(exceptFor, g.NAME)) {
      skipped.push({ name: g.NAME, reason: exceptFor[g.NAME].reason });
      continue;
    }
    var merged = Object.assign({}, baseOpts);
    if (Object.prototype.hasOwnProperty.call(override, g.NAME)) {
      merged = Object.assign(merged, override[g.NAME]);
    }
    active.push({ guard: g, opts: merged });
  }
  return { active: active, skipped: skipped };
}

// _emitCreationAudit — fires once per gate creation, recording the full
// active + skipped roster so a security review can reconstruct what
// this deploy did and didn't defend against.
function _emitCreationAudit(opts, resolved) {
  if (!opts.audit || typeof opts.audit.emit !== "function") return;
  try {
    opts.audit.emit({
      event:    "guardAll.gate.created",
      outcome:  "success",
      metadata: {
        profile:           opts.profile || null,
        compliancePosture: opts.compliancePosture || null,
        mode:              opts.mode || "enforce",
        active:            resolved.active.map(function (e) { return e.guard.NAME; }),
        skipped:           resolved.skipped,
      },
    });
  } catch (_e) {
    // best-effort audit emission; never fails the gate creation.
  }
}

// ---- Public surface ----

/**
 * @primitive b.guardAll.gate
 * @signature b.guardAll.gate(opts)
 * @since     0.7.16
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.guardAll.byExtension, b.guardAll.byContentType, b.guardAll.list
 *
 * Build a single composite gate that dispatches by `Content-Type` to
 * the active member of every registered content-bytes guard. Active
 * set is the full GUARDS list minus any names listed in `exceptFor`
 * (each requires a non-empty `reason` string — opting a guard out is
 * auditable). A `guardAll.gate.created` audit row records the active +
 * skipped roster so a security review can reconstruct what this deploy
 * did and didn't defend against.
 *
 * @opts
 *   profile:               "strict" | "balanced" | "permissive",
 *   compliancePosture:     "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   mode:                  "enforce" | "audit-only",
 *   exceptFor:             { [name]: { reason: string } },
 *   override:              { [name]: object },          // per-guard opts merged in
 *   audit:                 object,                      // b.audit handle
 *   observability:         object,                      // b.observability handle
 *   forensicEvidenceStore: object,
 *   forensicSnippetBytes:  number,
 *   cache:                 object,
 *   cacheTtlMs:            number,
 *   maxRuntimeMs:          number,
 *   beforeCheck:           function,
 *   afterCheck:            function,
 *   onIssue:               function,
 *   onSanitize:            function,
 *   onRefuse:              function,
 *   onAudit:               function,
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var safety = b.guardAll.gate({
 *     profile: "strict",
 *     exceptFor: {
 *       html: { reason: "every HTML response is server-rendered + CSP-locked" },
 *     },
 *     override: { csv: { profile: "email-attachment" } },
 *   });
 *   // → contentTypeMux gate dispatching by Content-Type to each active member
 */
function gate(opts) {
  opts = opts || {};
  var resolved = _resolveActiveGuards(opts);
  _emitCreationAudit(opts, resolved);

  var byMime = Object.create(null);
  for (var i = 0; i < resolved.active.length; i += 1) {
    var entry = resolved.active[i];
    var entryGate = entry.guard.gate(entry.opts);
    entry.guard.MIME_TYPES.forEach(function (m) {
      byMime[m.toLowerCase()] = entryGate;
    });
  }
  return gateContract.contentTypeMux(byMime, {
    name: "guardAll:" + (opts.profile || opts.compliancePosture || "default"),
  });
}

/**
 * @primitive b.guardAll.byExtension
 * @signature b.guardAll.byExtension(opts)
 * @since     0.7.16
 * @status    stable
 * @related   b.guardAll.gate, b.guardAll.byContentType
 *
 * Return a map of file extension (".csv", ".svg", ...) to the gate of
 * the guard that owns it. Drops directly into `b.staticServe.create
 * ({ contentSafety })` so on-disk content is gated by extension match
 * rather than served Content-Type. Honours the same `exceptFor` /
 * `override` shape as `gate()`.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   exceptFor:         { [name]: { reason: string } },
 *   override:          { [name]: object },
 *   audit:             object,
 *   observability:     object,
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var byExt = b.guardAll.byExtension({ profile: "strict" });
 *   var csvGate = byExt[".csv"];
 *   // → b.gateContract gate for guard-csv at strict profile
 */
function byExtension(opts) {
  opts = opts || {};
  var resolved = _resolveActiveGuards(opts);
  _emitCreationAudit(opts, resolved);

  var map = Object.create(null);
  for (var i = 0; i < resolved.active.length; i += 1) {
    var entry = resolved.active[i];
    var entryGate = entry.guard.gate(entry.opts);
    entry.guard.EXTENSIONS.forEach(function (e) {
      map[e.toLowerCase()] = entryGate;
    });
  }
  return map;
}

/**
 * @primitive b.guardAll.byContentType
 * @signature b.guardAll.byContentType(opts)
 * @since     0.7.16
 * @status    stable
 * @related   b.guardAll.gate, b.guardAll.byExtension
 *
 * Return a map of canonical MIME type to the gate of the guard that
 * owns it. Useful when the operator already has a non-mux dispatch
 * shape (custom router / per-route content-safety) and wants the
 * per-type gate keyed by MIME directly. `gate()` wraps this map in
 * `gateContract.contentTypeMux`; this primitive surfaces the raw map.
 *
 * @opts
 *   profile:           "strict" | "balanced" | "permissive",
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   exceptFor:         { [name]: { reason: string } },
 *   override:          { [name]: object },
 *   audit:             object,
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var byMime = b.guardAll.byContentType({ profile: "balanced" });
 *   var jsonGate = byMime["application/json"];
 *   // → b.gateContract gate for guard-json at balanced profile
 */
function byContentType(opts) {
  opts = opts || {};
  var resolved = _resolveActiveGuards(opts);
  _emitCreationAudit(opts, resolved);

  var map = Object.create(null);
  for (var i = 0; i < resolved.active.length; i += 1) {
    var entry = resolved.active[i];
    var entryGate = entry.guard.gate(entry.opts);
    entry.guard.MIME_TYPES.forEach(function (m) {
      map[m.toLowerCase()] = entryGate;
    });
  }
  return map;
}

/**
 * @primitive b.guardAll.list
 * @signature b.guardAll.list()
 * @since     0.7.16
 * @status    stable
 * @related   b.guardAll.allGuards, b.guardAll.gate
 *
 * Enumerate the registered content-bytes guards with their NAME, owned
 * MIME types, owned extensions, and supported profile + posture
 * vocabularies. Operators dump this at boot to surface "what is my
 * deploy actually defending" in their audit attestation.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rows = b.guardAll.list();
 *   // → [{ name: "csv", mimeTypes: ["text/csv"], extensions: [".csv"],
 *   //      profiles: ["strict","balanced","permissive","email-attachment"],
 *   //      postures: ["hipaa","pci-dss","gdpr","soc2"] }, ...]
 */
function list() {
  return GUARDS.map(function (g) {
    return {
      name:       g.NAME,
      mimeTypes:  g.MIME_TYPES.slice(),
      extensions: g.EXTENSIONS.slice(),
      profiles:   Object.keys(g.PROFILES),
      postures:   Object.keys(g.COMPLIANCE_POSTURES),
    };
  });
}

/**
 * @primitive b.guardAll.allGuards
 * @signature b.guardAll.allGuards()
 * @since     0.7.16
 * @status    stable
 * @related   b.guardAll.list, b.guardAll.gate
 *
 * Return every guard module in the family — registered (content-bytes)
 * AND standalone (filename / domain / uuid / cidr / time / mime / jwt /
 * oauth / graphql / shell / regex / jsonpath / template / image / pdf /
 * auth). Used by the adaptive integration harness to iterate the full
 * family without hardcoding the list, so future guards added to either
 * registry pick up automatically.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var all = b.guardAll.allGuards();
 *   var names = all.map(function (g) { return g.NAME; });
 *   // → ["csv","html","svg","archive","json","yaml","xml","markdown",
 *   //    "email","filename","domain","uuid","cidr","time","mime","jwt",
 *   //    "oauth","graphql","shell","regex","jsonpath","template",
 *   //    "image","pdf","auth"]
 */
function allGuards() {
  return GUARDS.concat(STANDALONE_GUARDS);
}

module.exports = {
  gate:              gate,
  byExtension:       byExtension,
  byContentType:     byContentType,
  list:              list,
  allGuards:         allGuards,
  GUARDS:            Object.freeze(GUARDS.slice()),
  STANDALONE_GUARDS: Object.freeze(STANDALONE_GUARDS.slice()),
  SHARED_PROFILES:   SHARED_PROFILES,
  SHARED_POSTURES:   SHARED_POSTURES,
  GuardAllError:     GuardAllError,
};
