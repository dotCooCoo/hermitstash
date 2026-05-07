"use strict";
/**
 * b.honeytoken — canary credential framework. Generates decoy values
 * (fake api-key shapes, fake admin URLs, fake DB row references) that
 * are NEVER handed to a real client; their presence in a request,
 * log, or DB lookup means an attacker found something they shouldn't
 * have. The framework registers each token at issuance and refuses
 * silently in production but always emits a `honeytoken.tripped`
 * audit row on any positive lookup.
 *
 *   var honey = b.honeytoken.create({ audit: b.audit });
 *
 *   var token = honey.issue({
 *     kind:     "apiKey",
 *     metadata: { plantedAt: "GET /admin/keys/404", linkedTo: "u_42" },
 *   });
 *   // → { value: "bk_canary_8f3a7b2e0c…", id: "ht_<hex>" }
 *
 *   if (honey.lookup(req.headers["x-api-key"])) {
 *     // attacker is using the canary; tripped event already audited
 *     return res.status(403).end();
 *   }
 *
 * Canary value shapes (`kind`):
 *   - "apiKey"   → `bk_canary_<32 hex>` (matches b.apiKey shape)
 *   - "session"  → `bks_canary_<48 hex>` (matches b.session shape)
 *   - "url"      → `/admin/canary-<32 hex>` (planted as a clickable link)
 *   - "rowId"    → `ht_canary_<32 hex>` (planted as a fake foreign key)
 *
 * Audit shape:
 *   - `honeytoken.issued` — outcome=success; metadata: { id, kind }
 *   - `honeytoken.tripped` — outcome=failure; metadata: { id, kind,
 *     metadata, observedAt, observedActor }
 */

var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var HoneytokenError = defineClass("HoneytokenError", { alwaysPermanent: true });

var KINDS = Object.freeze({
  apiKey:  function () { return "bk_canary_"  + crypto.generateToken(16); },     // allow:raw-byte-literal — 16-byte (128-bit) canary entropy
  session: function () { return "bks_canary_" + crypto.generateToken(24); },     // allow:raw-byte-literal — 24-byte (192-bit) canary entropy
  url:     function () { return "/admin/canary-" + crypto.generateToken(16); },  // allow:raw-byte-literal — 16-byte canary entropy
  rowId:   function () { return "ht_canary_"  + crypto.generateToken(16); },     // allow:raw-byte-literal — 16-byte canary entropy
});

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
    var id = "ht_" + crypto.generateToken(8);                                    // allow:raw-byte-literal — 8-byte registry id
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
