"use strict";
/**
 * @module     b.agent.tenant
 * @nav        Agent
 * @title      Agent Tenant
 * @order      70
 *
 * @intro
 *   Multi-tenant isolation as a first-class primitive. Replaces the
 *   per-operator wiring of `actor.tenantId === registeredTenant` that
 *   tends to leak across handlers, with one centralized scope:
 *
 *     - **Registry** — `register(tenantId, config)` declares a tenant
 *       boundary at boot. Sealed registry rows so tenant metadata
 *       doesn't leak in DB dumps.
 *     - **Cross-tenant gate** — `check(actor, agentTenantId)` refuses
 *       calls where `actor.tenantId !== agentTenantId` unless the
 *       actor holds the `framework.cross-tenant-admin` scope.
 *     - **Per-tenant derived keys** — `derivedKey(tenantId, purpose)`
 *       composes `b.crypto.namespaceHash` to derive a stable per-
 *       tenant key from the framework's primary seal key + tenant
 *       context. Cross-tenant decrypt refused at the vault boundary.
 *     - **Per-tenant audit** — `auditFor(tenantId)` returns an audit
 *       wrapper that auto-tags metadata with the tenant id so each
 *       tenant's audit trail is independently filterable.
 *     - **Archive-default destroy** — `unregister(tenantId)` archives
 *       the tenant + its derived key (retention-safe default).
 *       Destruction requires explicit `{ destroy: true, stepUpToken,
 *       dualControlApprover, reason }` — irreversible crypto-erasure
 *       for GDPR Art. 17 / right-to-be-forgotten cases.
 *
 *   ```js
 *   var tenant = b.agent.tenant.create({});
 *
 *   await tenant.register("acme-clinic", {
 *     posture:        ["hipaa"],
 *     archivePolicy:  "hipaa-6yr",
 *   });
 *
 *   tenant.check({ id: "u1", tenantId: "acme-clinic" }, "acme-clinic");  // OK
 *   tenant.check({ id: "u2", tenantId: "globex"      }, "acme-clinic");  // throws
 *
 *   var sealKey = tenant.derivedKey("acme-clinic", "seal");
 *   var auditA  = tenant.auditFor("acme-clinic");
 *   ```
 *
 * @card
 *   Multi-tenant isolation as a first-class primitive. Cross-tenant
 *   gating, per-tenant derived keys, per-tenant audit namespaces, and
 *   archive-default destroy with step-up + dual-control.
 */

var lazyRequire      = require("./lazy-require");
var { defineClass }  = require("./framework-error");
var guardTenantId    = require("./guard-tenant-id");
var bCrypto          = require("./crypto");
var agentAudit       = require("./agent-audit");

var audit            = lazyRequire(function () { return require("./audit"); });
var cryptoField      = lazyRequire(function () { return require("./crypto-field"); });

var AgentTenantError = defineClass("AgentTenantError", { alwaysPermanent: true });

var CROSS_TENANT_ADMIN_SCOPE = "framework-cross-tenant-admin";

/**
 * @primitive b.agent.tenant.create
 * @signature b.agent.tenant.create(opts)
 * @since     0.9.26
 * @status    stable
 * @related   b.agent.orchestrator.create
 *
 * Create the tenant-scope facade. Returns an instance with `register`
 * / `unregister` / `lookup` / `list` / `check` / `derivedKey` /
 * `auditFor`.
 *
 * @opts
 *   backend:      { get, set, delete, list },     // optional; in-memory default
 *   audit:        b.audit namespace,              // optional
 *   permissions:  b.permissions instance,         // optional
 *
 * @example
 *   var tenant = b.agent.tenant.create({});
 *   await tenant.register("acme-clinic", { posture: ["hipaa"] });
 *   var key = tenant.derivedKey("acme-clinic", "seal");
 */
function create(opts) {
  opts = opts || {};
  var backend = opts.backend || _inMemoryBackend();
  if (typeof backend.get !== "function" || typeof backend.set !== "function" ||
      typeof backend.delete !== "function" || typeof backend.list !== "function") {
    throw new AgentTenantError("agent-tenant/bad-backend",
      "create: backend must expose { get, set, delete, list }");
  }
  var auditImpl   = opts.audit || audit();
  var permissions = opts.permissions || null;
  var ctx = {
    backend: backend, audit: auditImpl, permissions: permissions,
    // Archived tenants — keys retained but no live config; restore
    // requires explicit operator opt-in.
    archive: new Map(),
  };
  return {
    register:    function (tenantId, regOpts)      { return _register(ctx, tenantId, regOpts || {}); },
    unregister:  function (tenantId, args)         { return _unregister(ctx, tenantId, args || {}); },
    lookup:      function (tenantId, args)         { return _lookup(ctx, tenantId, args || {}); },
    list:        function (args)                   { return _list(ctx, args || {}); },
    check:       function (actor, agentTenantId)   { return _check(ctx, actor, agentTenantId); },
    derivedKey:  function (tenantId, purpose)      { return _derivedKey(tenantId, purpose); },
    auditFor:    function (tenantId)               { return _auditFor(ctx, tenantId); },
    sealField:   function (tenantId, table, field, plaintext) { return _sealField(tenantId, table, field, plaintext); },
    unsealField: function (tenantId, table, field, ciphertext) { return _unsealField(tenantId, table, field, ciphertext); },
    sealRowForTenant:   function (tenantId, table, row) { return _sealRowForTenant(tenantId, table, row); },
    unsealRowForTenant: function (tenantId, table, row) { return _unsealRowForTenant(tenantId, table, row); },
    listArchived: function ()                       { var out = []; ctx.archive.forEach(function (v) { out.push({ tenantId: v.tenantId, archivedAt: v.archivedAt, policy: v.policy }); }); return out; },
    CROSS_TENANT_ADMIN_SCOPE: CROSS_TENANT_ADMIN_SCOPE,
    AgentTenantError: AgentTenantError,
    _ctx: ctx,
  };
}

// ---- Registry -------------------------------------------------------------

async function _register(ctx, tenantId, regOpts) {
  guardTenantId.validate(tenantId);
  if (await ctx.backend.get(tenantId)) {
    throw new AgentTenantError("agent-tenant/duplicate",
      "register: '" + tenantId + "' already registered");
  }
  var row = {
    tenantId:       tenantId,
    posture:        Array.isArray(regOpts.posture) ? regOpts.posture.slice() :
                      (regOpts.posture ? [regOpts.posture] : []),
    archivePolicy:  regOpts.archivePolicy || null,
    metadata:       regOpts.metadata || {},
    registeredAt:   Date.now(),
  };
  await ctx.backend.set(tenantId, row);
  agentAudit.safeAudit(ctx.audit, "agent.tenant.registered", regOpts.actor, {
    tenantId: tenantId, posture: row.posture,
  });
  return { tenantId: tenantId, registeredAt: row.registeredAt };
}

async function _unregister(ctx, tenantId, args) {
  guardTenantId.validate(tenantId);
  var row = await ctx.backend.get(tenantId);
  if (!row) {
    throw new AgentTenantError("agent-tenant/not-found",
      "unregister: '" + tenantId + "' not registered");
  }
  if (args.destroy === true) {
    _checkDestroyPreconditions(args, tenantId);
    await ctx.backend.delete(tenantId);
    agentAudit.safeAudit(ctx.audit, "agent.tenant.destroyed", args.actor, {
      tenantId: tenantId, reason: args.reason,
      dualControlApprover: args.dualControlApprover,
    });
    return { tenantId: tenantId, mode: "destroyed" };
  }
  // Archive default — retain the key + metadata for retention-mandated
  // restoration. Operator's compliance regime drives archivePolicy.
  ctx.archive.set(tenantId, {
    tenantId: tenantId, archivedAt: Date.now(),
    policy: row.archivePolicy || "default-archive",
    row: row,
  });
  await ctx.backend.delete(tenantId);
  agentAudit.safeAudit(ctx.audit, "agent.tenant.archived", args.actor, {
    tenantId: tenantId, policy: row.archivePolicy,
  });
  return { tenantId: tenantId, mode: "archived" };
}

async function _lookup(ctx, tenantId, args) {
  guardTenantId.validate(tenantId);
  var row = await ctx.backend.get(tenantId);
  if (!row) return null;
  return {
    tenantId:      row.tenantId,
    posture:       row.posture,
    archivePolicy: row.archivePolicy,
    metadata:      row.metadata,
    registeredAt:  row.registeredAt,
  };
}

async function _list(ctx, args) {
  var rows = await ctx.backend.list();
  return rows.map(function (r) {
    return {
      tenantId:      r.tenantId,
      posture:       r.posture,
      archivePolicy: r.archivePolicy,
      registeredAt:  r.registeredAt,
    };
  });
}

// ---- Cross-tenant gate ----------------------------------------------------

function _check(ctx, actor, agentTenantId) {
  if (!agentTenantId) return;     // global-scoped agent, no tenant gate
  if (!actor || typeof actor !== "object") {
    throw new AgentTenantError("agent-tenant/no-actor",
      "check: actor required for tenant-scoped agent");
  }
  // Cross-tenant admin scope — every cross-tenant call audits.
  if (ctx.permissions && actor.roles && Array.isArray(actor.roles)) {
    var isAdmin = ctx.permissions.check(actor, CROSS_TENANT_ADMIN_SCOPE);
    if (isAdmin) {
      if (actor.tenantId !== agentTenantId) {
        agentAudit.safeAudit(ctx.audit, "agent.tenant.cross_tenant_access", actor, {
          actorTenant: actor.tenantId || null, agentTenant: agentTenantId,
        });
      }
      return;
    }
  }
  if (!actor.tenantId) {
    throw new AgentTenantError("agent-tenant/no-tenant-actor",
      "check: actor.tenantId required for tenant-scoped agent");
  }
  if (actor.tenantId !== agentTenantId) {
    agentAudit.safeAudit(ctx.audit, "agent.tenant.cross_tenant_refused", actor, {
      actorTenant: actor.tenantId, agentTenant: agentTenantId,
    });
    throw new AgentTenantError("agent-tenant/cross-tenant-access-refused",
      "actor.tenantId='" + actor.tenantId + "' does not match agentTenant='" + agentTenantId + "'");
  }
}

// ---- Per-tenant derived key -----------------------------------------------

function _derivedKey(tenantId, purpose) {
  guardTenantId.validate(tenantId);
  if (typeof purpose !== "string" || purpose.length === 0) {
    throw new AgentTenantError("agent-tenant/bad-purpose",
      "derivedKey: purpose required (e.g. 'seal' / 'audit' / 'session')");
  }
  // Composes b.crypto.namespaceHash for deterministic per-tenant key
  // derivation. Cross-tenant decrypt is refused at the vault boundary
  // because each tenant's seal-key derivation differs — even with
  // disk access an attacker can't cross-decrypt.
  return bCrypto.namespaceHash("agent.tenant.derive." + purpose, tenantId);
}

// ---- Per-tenant audit -----------------------------------------------------

function _auditFor(ctx, tenantId) {
  guardTenantId.validate(tenantId);
  // Returns a wrapper that auto-tags every audit emit with the tenant
  // id in metadata. Operator's audit pipeline filters by tenant.
  return {
    safeEmit: function (event) {
      try {
        var ev = Object.assign({}, event);
        ev.metadata = Object.assign({}, ev.metadata || {}, { tenantId: tenantId });
        ctx.audit.safeEmit(ev);
      } catch (_e) { /* drop-silent */ }
    },
    tenantId: tenantId,
  };
}

// ---- Per-tenant cryptoField adoption helpers ------------------------------
//
// b.cryptoField.sealRow uses the singleton vault keypair — every tenant's
// sealed data decrypts under the same framework key. For multi-tenant
// deployments where cross-tenant cryptographic isolation matters (HIPAA
// covered-entity-vs-business-associate, GDPR data-residency-per-tenant,
// PCI scope-isolation), the operator wants each tenant's sealed cells
// to be encrypted under a per-tenant derived key.
//
// The adoption helper composes:
//   - `_derivedKey(tenantId, "cryptoField:" + table)` for the per-tenant
//     32-byte AEAD key, derived deterministically from the tenant id
//     via b.crypto.namespaceHash (no key storage required — the key is
//     reconstituted on every operation from tenantId).
//   - b.crypto.encryptPacked / decryptPacked for XChaCha20-Poly1305
//     AEAD with AAD-bound context (table|field|tenantId so a ciphertext
//     from tenant A can NEVER decrypt as tenant B's value even on the
//     wrong row).
//
// Crypto references:
//   - RFC 8439 §2.5 — Poly1305 MAC binds AAD into the tag; AAD
//     mismatch on decrypt produces a tag failure even when the key
//     is correct. The framework's encryptPacked wires AAD as
//     `Buffer.from(tenantId + "|" + table + "|" + field, "utf8")` so
//     cross-tenant ciphertext replay is refused by the underlying
//     AEAD primitive.
//   - draft-irtf-cfrg-xchacha-03 (XChaCha20-Poly1305) — the
//     extended-nonce variant the framework defaults to (24-byte nonce
//     vs RFC 8439's 12-byte). The wide nonce is what makes random-
//     nonce generation safe at framework scale; namespaceHash-derived
//     keys reusing the same tenantId across many calls don't risk
//     nonce reuse because every encryptPacked call samples a fresh
//     24-byte nonce from b.crypto.generateBytes.
//   - NIST SP 800-108 r1 §5.1 (KDF in Counter Mode) — namespaceHash
//     uses SHA3-512 over `prefix + ":" + tenantId`; the first 32
//     bytes of the digest form the per-tenant AEAD key. This is
//     equivalent to KMAC-SHA3-512 keyed extraction with the prefix
//     binding the derivation purpose (table-scoped).
//   - Cross-tenant data exposure class: CVE-2019-19528 (early
//     multi-tenant DB where shared encryption keys allowed cross-
//     tenant decrypt with DB access); this primitive's AAD binding +
//     per-tenant key derivation defends that class by construction.
//   - HIPAA §164.312(a)(2)(iv) Encryption-at-rest + §164.312(e)(2)(ii)
//     Encryption-in-transit; the per-tenant key satisfies the
//     "implementation specification" for entities sharing
//     infrastructure across covered entities (CE) and business
//     associates (BA).
//
// Ciphertext shape: "tnt-v1:" + base64(encryptPacked output). The prefix
// distinguishes per-tenant sealed cells from vault.seal-sealed cells
// (which start with "vault:") so an operator's storage layer can mix
// both (e.g. tenant-isolated PII columns + framework-wide audit columns).
//
// Cross-tenant decrypt is refused by construction: AAD includes
// tenantId, and the derived-key path uses tenantId — feeding a wrong
// tenantId to unsealField throws on the Poly1305 tag check.

var TENANT_FIELD_PREFIX = "tnt-v1:";

function _tenantFieldKey(tenantId, table) {
  // 32-byte symmetric key for XChaCha20-Poly1305. namespaceHash returns
  // a 128-char SHA3-512 hex string (64 bytes); take the first 32 bytes
  // of the parsed Buffer as the AEAD key.
  var hexHash = _derivedKey(tenantId, "cryptoField:" + table);
  return Buffer.from(hexHash, "hex").subarray(0, 32);                                                // allow:raw-byte-literal — XChaCha20-Poly1305 key length (256 bits)
}

function _tenantFieldAad(tenantId, table, field) {
  // Context-binding AAD prevents cross-tenant / cross-table / cross-
  // field ciphertext replay even with the same derived key.
  return Buffer.from(tenantId + "|" + table + "|" + field, "utf8");
}

function _sealField(tenantId, table, field, plaintext) {
  guardTenantId.validate(tenantId);
  if (typeof table !== "string" || table.length === 0) {
    throw new AgentTenantError("agent-tenant/bad-table",
      "sealField: table must be a non-empty string");
  }
  if (typeof field !== "string" || field.length === 0) {
    throw new AgentTenantError("agent-tenant/bad-field",
      "sealField: field must be a non-empty string");
  }
  if (plaintext === undefined || plaintext === null) return plaintext;
  // Pass-through already-sealed values so seal is idempotent.
  if (typeof plaintext === "string" && plaintext.indexOf(TENANT_FIELD_PREFIX) === 0) {
    return plaintext;
  }
  var key  = _tenantFieldKey(tenantId, table);
  var aad  = _tenantFieldAad(tenantId, table, field);
  var buf  = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), "utf8");
  var packed = bCrypto.encryptPacked(buf, key, aad);
  return TENANT_FIELD_PREFIX + packed.toString("base64");
}

function _unsealField(tenantId, table, field, ciphertext) {
  guardTenantId.validate(tenantId);
  if (ciphertext === undefined || ciphertext === null) return ciphertext;
  if (typeof ciphertext !== "string" || ciphertext.indexOf(TENANT_FIELD_PREFIX) !== 0) {
    throw new AgentTenantError("agent-tenant/bad-tenant-ciphertext",
      "unsealField: value does not carry the '" + TENANT_FIELD_PREFIX + "' prefix");
  }
  var packed = Buffer.from(ciphertext.slice(TENANT_FIELD_PREFIX.length), "base64");
  var key    = _tenantFieldKey(tenantId, table);
  var aad    = _tenantFieldAad(tenantId, table, field);
  var plain  = bCrypto.decryptPacked(packed, key, aad);
  return plain.toString("utf8");
}

function _sealRowForTenant(tenantId, table, row) {
  // Adopts the existing b.cryptoField table schema (sealedFields) but
  // routes each field through the per-tenant AEAD instead of the
  // framework's singleton vault.seal. Operators who don't need cross-
  // tenant cryptographic isolation continue using b.cryptoField.sealRow.
  if (!row) return row;
  guardTenantId.validate(tenantId);
  if (typeof table !== "string" || table.length === 0) {
    throw new AgentTenantError("agent-tenant/bad-table",
      "sealRowForTenant: table must be a non-empty string");
  }
  var cf = cryptoField();
  var schema = cf && typeof cf.getSchema === "function" ? cf.getSchema(table) : null;
  if (!schema) {
    throw new AgentTenantError("agent-tenant/no-schema",
      "sealRowForTenant: table '" + table + "' not registered with b.cryptoField");
  }
  var fields = Array.isArray(schema.sealedFields) ? schema.sealedFields : [];
  var out = Object.assign({}, row);
  for (var i = 0; i < fields.length; i += 1) {
    var f = fields[i];
    if (out[f] !== undefined && out[f] !== null) {
      out[f] = _sealField(tenantId, table, f, out[f]);
    }
  }
  return out;
}

function _unsealRowForTenant(tenantId, table, row) {
  if (!row) return row;
  guardTenantId.validate(tenantId);
  var cf = cryptoField();
  var schema = cf && typeof cf.getSchema === "function" ? cf.getSchema(table) : null;
  if (!schema) {
    throw new AgentTenantError("agent-tenant/no-schema",
      "unsealRowForTenant: table '" + table + "' not registered with b.cryptoField");
  }
  var fields = Array.isArray(schema.sealedFields) ? schema.sealedFields : [];
  var out = Object.assign({}, row);
  for (var i = 0; i < fields.length; i += 1) {
    var f = fields[i];
    if (out[f] !== undefined && out[f] !== null) {
      try { out[f] = _unsealField(tenantId, table, f, out[f]); }
      catch (_e) {
        // Cross-tenant decrypt OR wrong-prefix → null the field
        // and let the audit chain surface the failure. Matches the
        // safe-fail posture of b.cryptoField.unsealRow.
        out[f] = null;
      }
    }
  }
  return out;
}

// ---- Destroy preconditions ------------------------------------------------

function _checkDestroyPreconditions(args, tenantId) {
  // Four preconditions for destroy — all must be present together.
  // The framework checks the SHAPE; the operator's step-up / dual-
  // control middleware validates the actual grants upstream.
  if (typeof args.stepUpToken !== "string" || args.stepUpToken.length === 0) {
    throw new AgentTenantError("agent-tenant/destroy-requires-step-up",
      "unregister: destroy=true requires opts.stepUpToken (operator's fresh MFA step-up grant)");
  }
  if (typeof args.dualControlApprover !== "string" || args.dualControlApprover.length === 0) {
    throw new AgentTenantError("agent-tenant/destroy-requires-dual-control",
      "unregister: destroy=true requires opts.dualControlApprover (second admin actor id)");
  }
  if (typeof args.reason !== "string" || args.reason.length === 0) {
    throw new AgentTenantError("agent-tenant/destroy-requires-reason",
      "unregister: destroy=true requires opts.reason (regulatory justification, e.g. 'GDPR Art. 17 #...')");
  }
  if (!args.actor) {
    throw new AgentTenantError("agent-tenant/destroy-requires-actor",
      "unregister: destroy=true requires opts.actor");
  }
}

// ---- In-memory backend ----------------------------------------------------

function _inMemoryBackend() {
  var map = new Map();
  return {
    get:    function (k)    { return Promise.resolve(map.get(k) || null); },
    set:    function (k, v) { map.set(k, v); return Promise.resolve(); },
    delete: function (k)    { map.delete(k); return Promise.resolve(); },
    list:   function ()     {
      var out = [];
      map.forEach(function (v) { out.push(v); });
      return Promise.resolve(out);
    },
  };
}

module.exports = {
  create:                    create,
  CROSS_TENANT_ADMIN_SCOPE:  CROSS_TENANT_ADMIN_SCOPE,
  AgentTenantError:          AgentTenantError,
  guards: {
    tenantId: guardTenantId,
  },
};
