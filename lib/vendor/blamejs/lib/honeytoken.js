"use strict";
/**
 * @module b.honeytoken
 * @nav    Identity
 * @title  Honeytoken
 *
 * @intro
 *   Framework-seeded canary records that trigger an audit alert on
 *   read; integrates with sealed columns. The framework generates
 *   decoy values (fake api-key shapes, fake admin URLs, fake DB row
 *   references) that are NEVER handed to a real client. Their
 *   presence in a request, log, or DB lookup means an attacker
 *   reached something they shouldn't have. Every positive lookup
 *   emits a `honeytoken.tripped` audit row with the observing
 *   actor's 5 W's so a SOC operator can pivot directly to the
 *   compromise.
 *
 *   Canary value shapes (`kind`):
 *     - `"apiKey"`  — `bk_canary_<hex>` (mirrors b.apiKey shape)
 *     - `"session"` — `bks_canary_<hex>` (mirrors b.session shape)
 *     - `"url"`     — `/admin/canary-<hex>` (planted as a clickable link)
 *     - `"rowId"`   — `ht_canary_<hex>` (planted as a fake foreign key)
 *
 *   Audit shape:
 *     - `honeytoken.issued`  — outcome=success; metadata { id, kind }
 *     - `honeytoken.tripped` — outcome=failure; metadata { id, kind,
 *       metadata, observedAt, observedActor }
 *
 * @card
 *   Framework-seeded canary records that trigger an audit alert on read; integrates with sealed columns.
 */

var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var HoneytokenError = defineClass("HoneytokenError", { alwaysPermanent: true });

var KINDS = Object.freeze({
  apiKey:  function () { return "bk_canary_"  + bCrypto.generateToken(16); },     // allow:raw-byte-literal — 16-byte (128-bit) canary entropy
  session: function () { return "bks_canary_" + bCrypto.generateToken(24); },     // allow:raw-byte-literal — 24-byte (192-bit) canary entropy
  url:     function () { return "/admin/canary-" + bCrypto.generateToken(16); },  // allow:raw-byte-literal — 16-byte canary entropy
  rowId:   function () { return "ht_canary_"  + bCrypto.generateToken(16); },     // allow:raw-byte-literal — 16-byte canary entropy
});

/**
 * @primitive b.honeytoken.create
 * @signature b.honeytoken.create(opts)
 * @since     0.8.40
 * @status    stable
 * @compliance soc2, nis2, dora
 * @related   b.audit, b.apiKey.create, b.session
 *
 * Build an in-process honeytoken registry. Returns a handle exposing
 * `issue(spec)` to mint a canary, `lookup(value, observedActor?)` to
 * test an incoming value (audit-emits `honeytoken.tripped` on hit),
 * `revoke(id)` to retire a canary, and `size()` for diagnostics. The
 * registry is per-process — operators running multiple workers wire
 * a shared b.audit sink and reconcile alerts at the audit layer
 * rather than sharing the registry across nodes (a canary's value
 * is what's planted in the trap, not what's known to the framework).
 *
 * @opts
 *   audit:  b.audit,   // audit sink for issued / tripped events (optional, recommended)
 *
 * @example
 *   var honey = b.honeytoken.create({ audit: b.audit });
 *
 *   var canary = honey.issue({
 *     kind:     "apiKey",
 *     metadata: { plantedAt: "GET /admin/keys/list", linkedTo: "user-42" },
 *   });
 *   // → { id: "ht_<hex>", value: "bk_canary_<hex>" }
 *
 *   // Plant the canary value somewhere an attacker who's escalated
 *   // privileges might find it (a fake row in an admin listing, a
 *   // dummy env-var leaked into a traceback page, etc.).
 *
 *   // On every incoming credential, check for canary use:
 *   if (honey.lookup(req.headers["x-api-key"], { ip: req.ip })) {
 *     // tripped — audit already emitted; respond as if invalid.
 *     return res.writeHead(403).end();
 *   }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["audit"], "honeytoken.create");

  var registry = new Map();   // value → { id, kind, metadata, issuedAt }

  function issue(spec) {
    spec = spec || {};
    validateOpts(spec, ["kind", "metadata"], "honeytoken.issue");
    var kind = spec.kind;
    if (typeof KINDS[kind] !== "function") {
      throw new HoneytokenError(
        "honeytoken/unknown-kind",
        "honeytoken.issue: unknown kind '" + kind + "' " +
        "(supported: " + Object.keys(KINDS).join(", ") + ")");
    }
    var value = KINDS[kind]();
    var id = "ht_" + bCrypto.generateToken(8);                                    // allow:raw-byte-literal — 8-byte registry id
    var record = Object.freeze({
      id:        id,
      kind:      kind,
      metadata:  spec.metadata || null,
      issuedAt:  Date.now(),
    });
    registry.set(value, record);
    try {
      audit().safeEmit({
        action: "honeytoken.issued",
        outcome: "success",
        metadata: { id: id, kind: kind },
      });
    } catch (_e) { /* audit best-effort */ }
    return { id: id, value: value };
  }

  function lookup(value, observedActor) {
    if (typeof value !== "string" || value.length === 0) return null;
    var record = registry.get(value);
    if (!record) return null;
    try {
      audit().safeEmit({
        action: "honeytoken.tripped",
        outcome: "failure",
        metadata: {
          id:             record.id,
          kind:           record.kind,
          metadata:       record.metadata,
          observedAt:     Date.now(),
          observedActor:  observedActor || null,
        },
      });
    } catch (_e) { /* audit best-effort */ }
    return record;
  }

  function revoke(id) {
    var found = false;
    registry.forEach(function (record, value) {
      if (record.id === id) {
        registry.delete(value);
        found = true;
      }
    });
    return found;
  }

  function size() { return registry.size; }

  return {
    issue:   issue,
    lookup:  lookup,
    revoke:  revoke,
    size:    size,
  };
}

module.exports = {
  create:           create,
  KINDS:            Object.freeze(Object.keys(KINDS)),
  HoneytokenError:  HoneytokenError,
};
