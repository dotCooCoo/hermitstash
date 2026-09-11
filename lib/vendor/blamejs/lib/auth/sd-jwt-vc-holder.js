// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var sdJwtVcCore = lazyRequire(function () { return require("./sd-jwt-vc"); });
var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

var _HOLDER_EC_CURVE_ALG = { prime256v1: "ES256", secp384r1: "ES384" };

function _resolveHolderAlg(holderKey, explicitAlg) {
  if (explicitAlg) return explicitAlg;
  var keyObj = null;
  try {
    if (holderKey instanceof nodeCrypto.KeyObject) {
      keyObj = holderKey;
    } else if (typeof holderKey === "string" || Buffer.isBuffer(holderKey)) {
      keyObj = nodeCrypto.createPrivateKey({ key: holderKey, format: "pem" });
    } else if (holderKey && typeof holderKey === "object" && holderKey.kty) {
      keyObj = nodeCrypto.createPrivateKey({ key: holderKey, format: "jwk" });
    }
  } catch (_e) {
    keyObj = null;
  }
  if (!keyObj) return "ES256";
  var kty = keyObj.asymmetricKeyType;
  if (kty === "ec") {
    var curve = (keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.namedCurve) || "";
    var ecAlg = _HOLDER_EC_CURVE_ALG[curve];
    if (ecAlg) return ecAlg;
    throw new AuthError("auth-sd-jwt-vc/holder-key-unsupported",
      "holder.create: EC curve '" + curve + "' has no KB-JWT algorithm (use P-256 / P-384, Ed25519, or ML-DSA-87 / ML-DSA-65)");
  }
  if (kty === "ed25519" || kty === "ed448") return "EdDSA";
  if (kty === "ml-dsa-87") return "ML-DSA-87";
  if (kty === "ml-dsa-65") return "ML-DSA-65";
  throw new AuthError("auth-sd-jwt-vc/holder-key-unsupported",
    "holder.create: key type '" + String(kty) + "' has no KB-JWT algorithm (use EC P-256 / P-384, Ed25519, or ML-DSA-87 / ML-DSA-65; RSA is not supported for KB-JWT)");
}

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
  var algorithm = _resolveHolderAlg(opts.holderKey, opts.algorithm);
  var auditOn = opts.auditOn !== false;

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  var _emitMetric = observability().namespaced("auth.sdJwtVc.holder");

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
    if (spec.keyAttestation !== undefined && spec.keyAttestation !== null) {
      if (typeof spec.keyAttestation !== "string" ||
          spec.keyAttestation.split(".").length !== 3) {
        throw new AuthError("auth-sd-jwt-vc/bad-key-attestation",
          "holder.store: keyAttestation must be a JWS-compact-serialized JWT (3 dot-separated segments)");
      }
    }
    var record = {
      id:             spec.id,
      sdJwt:          spec.sdJwt,
      vct:            spec.vct || null,
      issuer:         spec.issuer || null,
      keyAttestation: spec.keyAttestation || null,
      receivedAt:     Date.now(),
    };
    await opts.storage.put(spec.id, record);
    _emitAudit("auth.sdJwtVc.holder.stored", "success", {
      id: spec.id, vct: record.vct, issuer: record.issuer,
      hasKeyAttestation: !!record.keyAttestation,
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
    var keyAttestation = spec.keyAttestation || record.keyAttestation || null;
    var presentation = sdJwtVcCore().present({
      sdJwt:               record.sdJwt,
      disclosedClaimNames: spec.disclosedClaimNames || [],
      audience:            spec.audience || null,
      nonce:               spec.nonce || null,
      holderKey:           opts.holderKey,
      algorithm:           algorithm,
      keyAttestation:      keyAttestation,
    });
    _emitAudit("auth.sdJwtVc.holder.presented", "success", {
      credentialId:       spec.credentialId,
      audience:           spec.audience || null,
      disclosed:          (spec.disclosedClaimNames || []).length,
      hasKeyAttestation:  !!keyAttestation,
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
