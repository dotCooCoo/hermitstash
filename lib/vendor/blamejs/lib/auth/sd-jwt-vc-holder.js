"use strict";
/**
 * b.auth.sdJwtVc.holder — operator-side holder/wallet helper.
 *
 * Wraps the lower-level present() function with key-management +
 * stored-credential lookup + per-presentation audit emission.
 * Operators running a wallet (mobile app backend, OIDC4VP relying
 * party with holder role) instantiate one of these per holder.
 *
 *   var holder = b.auth.sdJwtVc.holder.create({
 *     storage:       holderStorageBackend,    // operator-side persistence
 *     holderKey:     keyPemOrJwk,
 *     algorithm:     "ES256",
 *     auditOn:       true,
 *   });
 *
 *   // Save a credential the wallet just received from an issuer
 *   await holder.store({
 *     id:    "cred-1",
 *     sdJwt: receivedFromIssuer.token,
 *     vct:   "https://example.com/vct/identity",
 *     issuer: "https://issuer.example.com",
 *   });
 *
 *   // Build a presentation for a verifier request
 *   var presentation = await holder.present({
 *     credentialId:        "cred-1",
 *     disclosedClaimNames: ["given_name"],
 *     audience:            "https://verifier.example.com",
 *     nonce:               nonceFromVerifier,
 *   });
 *
 *   // List stored credentials
 *   var creds = await holder.list();
 *
 *   // Delete a credential (on revocation / user request / DSR erasure)
 *   await holder.delete("cred-1");
 *
 * Storage shape (operator implements):
 *   { put(id, record), get(id), list(), delete(id) }
 *
 * The framework also ships `memoryStorage()` for development /
 * tests — production operators wire b.db / b.objectStore.
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var sdJwtVcCore = lazyRequire(function () { return require("./sd-jwt-vc"); });
var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

function _validateStorage(storage) {
  if (!storage || typeof storage !== "object") return false;
  return ["put", "get", "list", "delete"].every(function (m) {
    return typeof storage[m] === "function";
  });
}

function memoryStorage() {
  var byId = new Map();
  return {
    put: async function (id, record) {
      byId.set(id, Object.assign({}, record, { id: id }));
    },
    get: async function (id) {
      var r = byId.get(id);
      return r ? Object.assign({}, r) : null;
    },
    list: async function () {
      return Array.from(byId.values()).map(function (r) {
        return Object.assign({}, r);
      });
    },
    delete: async function (id) {
      var existed = byId.has(id);
      byId.delete(id);
      return existed;
    },
    _size: function () { return byId.size; },
  };
}

function create(opts) {
  validateOpts.requireObject(opts, "auth.sdJwtVc.holder.create", AuthError);
  validateOpts(opts, [
    "storage", "holderKey", "algorithm", "auditOn",
  ], "auth.sdJwtVc.holder.create");

  if (!_validateStorage(opts.storage)) {
    throw new AuthError("auth-sd-jwt-vc/bad-storage",
      "holder.create: storage must implement { put, get, list, delete }");
  }
  if (!opts.holderKey) {
    throw new AuthError("auth-sd-jwt-vc/no-key",
      "holder.create: holderKey required");
  }
  var algorithm = opts.algorithm || "ES256";
  var auditOn = opts.auditOn !== false;

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _emitMetric(verb) {
    try { observability().safeEvent("auth.sdJwtVc.holder." + verb, 1, {}); }
    catch (_e) { /* drop-silent */ }
  }

  async function store(spec) {
    if (!spec || typeof spec !== "object") {
      throw new AuthError("auth-sd-jwt-vc/bad-spec",
        "holder.store: spec must be an object");
    }
    if (typeof spec.id !== "string" || spec.id.length === 0) {
      throw new AuthError("auth-sd-jwt-vc/bad-id",
        "holder.store: id is required");
    }
    if (typeof spec.sdJwt !== "string") {
      throw new AuthError("auth-sd-jwt-vc/bad-token",
        "holder.store: sdJwt is required");
    }
    var record = {
      id:        spec.id,
      sdJwt:     spec.sdJwt,
      vct:       spec.vct || null,
      issuer:    spec.issuer || null,
      receivedAt: Date.now(),
    };
    await opts.storage.put(spec.id, record);
    _emitAudit("auth.sdJwtVc.holder.stored", "success", {
      id: spec.id, vct: record.vct, issuer: record.issuer,
    });
    _emitMetric("stored");
    return record;
  }

  async function present(spec) {
    if (!spec || typeof spec !== "object") {
      throw new AuthError("auth-sd-jwt-vc/bad-spec",
        "holder.present: spec must be an object");
    }
    var record = await opts.storage.get(spec.credentialId);
    if (!record) {
      throw new AuthError("auth-sd-jwt-vc/credential-not-found",
        "holder.present: credentialId \"" + spec.credentialId + "\" not found in storage");
    }
    var presentation = sdJwtVcCore().present({
      sdJwt:               record.sdJwt,
      disclosedClaimNames: spec.disclosedClaimNames || [],
      audience:            spec.audience || null,
      nonce:               spec.nonce || null,
      holderKey:           opts.holderKey,
      algorithm:           algorithm,
    });
    _emitAudit("auth.sdJwtVc.holder.presented", "success", {
      credentialId: spec.credentialId,
      audience:     spec.audience || null,
      disclosed:    (spec.disclosedClaimNames || []).length,
    });
    _emitMetric("presented");
    return presentation;
  }

  async function list() {
    var rows = await opts.storage.list();
    return Array.isArray(rows) ? rows : [];
  }

  async function get(id) {
    return await opts.storage.get(id);
  }

  async function _delete(id) {
    var existed = await opts.storage.delete(id);
    if (existed) {
      _emitAudit("auth.sdJwtVc.holder.deleted", "success", { id: id });
      _emitMetric("deleted");
    }
    return existed;
  }

  return {
    store:    store,
    present:  present,
    list:     list,
    get:      get,
    delete:   _delete,
  };
}

module.exports = {
  create:        create,
  memoryStorage: memoryStorage,
};
