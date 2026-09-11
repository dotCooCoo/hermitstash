// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *       boundary at boot. The row's metadata is sealed at rest via
 *       `b.cryptoField` when a vault is configured (the default in a
 *       booted app), so tenant metadata doesn't leak in DB dumps.
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
var C                = require("./constants");
var { defineClass }  = require("./framework-error");
var guardTenantId    = require("./guard-tenant-id");
var bCrypto          = require("./crypto");
var agentAudit       = require("./agent-audit");
var safeJson         = require("./safe-json");
var vaultAad         = require("./vault-aad");
var validateOpts     = require("./validate-opts");
var safeAsync        = require("./safe-async");

var audit            = lazyRequire(function () { return require("./audit"); });
var cryptoField      = lazyRequire(function () { return require("./crypto-field"); });
var vault            = lazyRequire(function () { return require("./vault"); });

var AgentTenantError = defineClass("AgentTenantError", { alwaysPermanent: true });

var SEAL_TABLE = "agent_tenant_registry";
var _sealTableRegistered = false;
var SEAL_METADATA_MAX_BYTES = C.BYTES.mib(1);
function _ensureSealTable() {
  if (_sealTableRegistered) return;
  cryptoField().registerTable(SEAL_TABLE, {
    sealedFields: ["metadata"],
    aad:          true,
    rowIdField:   "tenantId",
  });
  _sealTableRegistered = true;
}
function _sealRegistryRow(row) {
  if (!vault().isInitialized()) return row;
  _ensureSealTable();
  var pre = Object.assign({}, row);
  if (pre.metadata !== undefined && pre.metadata !== null && typeof pre.metadata !== "string") {
    pre.metadata = safeJson.stringify(pre.metadata);
  }
  return cryptoField().sealRow(SEAL_TABLE, pre);
}
function _unsealMetadata(row) {
  if (!row) return row;
  if (!vault().isInitialized()) return row;
  _ensureSealTable();
  var out = cryptoField().unsealRow(SEAL_TABLE, row);
  if (typeof out.metadata === "string") {
    try { out.metadata = safeJson.parse(out.metadata, { maxBytes: SEAL_METADATA_MAX_BYTES }); }
    catch (_e) { /* legacy raw-string metadata — leave as-is */ }
  }
  return out;
}

var CROSS_TENANT_ADMIN_SCOPE = "framework-cross-tenant-admin";

var TENANT_KDF_LABEL = "blamejs.agent.tenant/v1";
var TENANT_KEY_BYTES = 32;

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
  validateOpts.requireMethods(backend, ["get", "set", "delete", "list"],
    "create: backend", AgentTenantError, "agent-tenant/bad-backend");
  var auditImpl   = opts.audit || audit();
  var permissions = opts.permissions || null;
  var ctx = {
    backend: backend, audit: auditImpl, permissions: permissions,
    registrySerializer: safeAsync.keyedSerializer(),
    archive: new Map(),
  };
  return {
    register:    function (tenantId, regOpts)      { return ctx.registrySerializer.run(tenantId, function () { return _register(ctx, tenantId, regOpts || {}); }); },
    unregister:  function (tenantId, args)         { return ctx.registrySerializer.run(tenantId, function () { return _unregister(ctx, tenantId, args || {}); }); },
    lookup:      function (tenantId, args)         { return _lookup(ctx, tenantId, args || {}); },
    list:        function (args)                   { return _list(ctx, args || {}); },
    check:       function (actor, agentTenantId)   { return _check(ctx, actor, agentTenantId); },
    derivedKey:  function (tenantId, purpose)      { return _derivedKey(tenantId, purpose); },
    auditFor:    function (tenantId)               { return _auditFor(ctx, tenantId); },
    sealField:   function (tenantId, table, field, plaintext) { return _sealField(tenantId, table, field, plaintext); },
    unsealField: function (tenantId, table, field, ciphertext) { return _unsealField(tenantId, table, field, ciphertext); },
    sealRowForTenant:   function (tenantId, table, row) { return _sealRowForTenant(tenantId, table, row); },
    unsealRowForTenant: function (tenantId, table, row) { return _unsealRowForTenant(ctx, tenantId, table, row); },
    listArchived: function ()                       { return _listArchived(ctx); },
    CROSS_TENANT_ADMIN_SCOPE: CROSS_TENANT_ADMIN_SCOPE,
    AgentTenantError: AgentTenantError,
    _ctx: ctx,
  };
}

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
  await ctx.backend.set(tenantId, _sealRegistryRow(row));
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
  var archivedRow = {
    tenantId:    tenantId,
    posture:     row.posture,
    archivePolicy: row.archivePolicy || "default-archive",
    metadata:    row.metadata,
    registeredAt: row.registeredAt,
    archivedAt:  Date.now(),
    status:      "archived",
  };
  ctx.archive.set(tenantId, {
    tenantId: tenantId, archivedAt: archivedRow.archivedAt,
    policy: archivedRow.archivePolicy, row: row,
  });
  if (typeof ctx.backend.archive === "function") {
    await ctx.backend.archive(tenantId, archivedRow);
  } else {
    await ctx.backend.set("__archived__/" + tenantId, archivedRow);
  }
  await ctx.backend.delete(tenantId);
  agentAudit.safeAudit(ctx.audit, "agent.tenant.archived", args.actor, {
    tenantId: tenantId, policy: archivedRow.archivePolicy,
  });
  return { tenantId: tenantId, mode: "archived" };
}

async function _lookup(ctx, tenantId, args) {
  guardTenantId.validate(tenantId);
  var row = await ctx.backend.get(tenantId);
  if (!row) return null;
  row = _unsealMetadata(row);
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
  return rows.filter(function (r) {
    return r && r.status !== "archived";
  }).map(function (r) {
    return {
      tenantId:      r.tenantId,
      posture:       r.posture,
      archivePolicy: r.archivePolicy,
      registeredAt:  r.registeredAt,
    };
  });
}

async function _listArchived(ctx) {
  var out = [];
  if (typeof ctx.backend.listArchived === "function") {
    var rows = await ctx.backend.listArchived();
    if (Array.isArray(rows)) {
      for (var i = 0; i < rows.length; i += 1) {
        out.push({
          tenantId:   rows[i].tenantId,
          archivedAt: rows[i].archivedAt,
          policy:     rows[i].archivePolicy || rows[i].policy || "default-archive",
        });
      }
    }
  } else {
    var allRows = await ctx.backend.list();
    if (Array.isArray(allRows)) {
      for (var j = 0; j < allRows.length; j += 1) {
        var r = allRows[j];
        if (r && r.status === "archived") {
          out.push({
            tenantId:   r.tenantId,
            archivedAt: r.archivedAt,
            policy:     r.archivePolicy || "default-archive",
          });
        }
      }
    }
  }
  ctx.archive.forEach(function (v) {
    var found = false;
    for (var k = 0; k < out.length; k += 1) {
      if (out[k].tenantId === v.tenantId) { found = true; break; }
    }
    if (!found) out.push({ tenantId: v.tenantId, archivedAt: v.archivedAt, policy: v.policy });
  });
  return out;
}

function _check(ctx, actor, agentTenantId) {
  if (!agentTenantId) return;
  if (!actor || typeof actor !== "object") {
    throw new AgentTenantError("agent-tenant/no-actor",
      "check: actor required for tenant-scoped agent");
  }
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

function _vaultRootBytes(rootKeysJson) {
  if (typeof rootKeysJson === "string" && rootKeysJson.length > 0) {
    return Buffer.from(bCrypto.sha3Hash(rootKeysJson), "hex");
  }
  var keysJson;
  try { keysJson = vault().getKeysJson(); }
  catch (e) {
    throw new AgentTenantError("agent-tenant/vault-not-initialized",
      "derivedKey: vault must be initialized before per-tenant keys can be " +
      "derived (vault.getKeysJson threw: " + (e && e.message ? e.message : String(e)) + ")");
  }
  return Buffer.from(bCrypto.sha3Hash(keysJson), "hex");
}

function _deriveTenantKeyBytes(tenantId, purpose, rootKeysJson) {
  guardTenantId.validate(tenantId);
  if (typeof purpose !== "string" || purpose.length === 0) {
    throw new AgentTenantError("agent-tenant/bad-purpose",
      "derivedKey: purpose required (e.g. 'seal' / 'audit' / 'session')");
  }
  var rootBytes = _vaultRootBytes(rootKeysJson);
  var input = Buffer.concat([
    Buffer.from(TENANT_KDF_LABEL, "utf8"),
    Buffer.from([0x00]),
    rootBytes,
    Buffer.from([0x00]),
    Buffer.from(tenantId, "utf8"),
    Buffer.from([0x00]),
    Buffer.from(purpose, "utf8"),
  ]);
  return bCrypto.kdf(input, TENANT_KEY_BYTES);
}

/**
 * @primitive b.agent.tenant.derivedKey
 * @signature b.agent.tenant.derivedKey(tenantId, purpose)
 * @since     0.9.26
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.agent.tenant.create, b.archive.wrap, b.vault
 *
 * Derive a deterministic, domain-separated 32-byte key for a tenant
 * and a named purpose, returned as a 64-char hex string. The key is a
 * SHAKE256 KDF over the vault root (the master keypair PEM hashed),
 * the `tenantId`, and the `purpose`, with NUL separators so distinct
 * `(tenantId, purpose)` pairs cannot collide. The same inputs always
 * produce the same key, so a value sealed under
 * `derivedKey(t, "archive-wrap")` is recoverable later from the same
 * tenant + purpose with no key escrow. Rotating the vault
 * (`b.vaultRotate.rotate`) changes the root and therefore every
 * derived key, so every cell sealed under the old root must be
 * re-sealed under the new one. That migration runs through the
 * module's `reseal` hook (eager-registered via `AAD_ROTATION`), not
 * silently on the next read — a value sealed under the old root does
 * not decrypt under the new root until the rotation pipeline walks it.
 *
 * Throws if the vault has not been initialized (keys cannot be derived
 * before bootstrap) or if `purpose` is empty. This is the same
 * derivation the per-tenant `sealField` / archive `recipient: "tenant"`
 * paths use internally; call it directly when you need the raw key for
 * your own AEAD.
 *
 * @example
 *   var key = b.agent.tenant.derivedKey("acme-corp", "archive-wrap");
 *   // → "9f3c…" (64 hex chars; deterministic per tenant + purpose)
 */
function _derivedKey(tenantId, purpose) {
  return _deriveTenantKeyBytes(tenantId, purpose).toString("hex");
}

function _auditFor(ctx, tenantId) {
  guardTenantId.validate(tenantId);
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

var TENANT_FIELD_PREFIX = "tnt-v1:";

function _tenantFieldKey(tenantId, table, rootKeysJson) {
  return _deriveTenantKeyBytes(tenantId, "cryptoField:" + table, rootKeysJson);
}

function _tenantFieldAad(tenantId, table, field) {
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

function _resealTenantCell(tenantId, table, field, ciphertext, oldRootJson, newRootJson) {
  if (typeof ciphertext !== "string" || ciphertext.indexOf(TENANT_FIELD_PREFIX) !== 0) {
    return ciphertext;
  }
  var packed = Buffer.from(ciphertext.slice(TENANT_FIELD_PREFIX.length), "base64");
  var aad    = _tenantFieldAad(tenantId, table, field);
  var oldKey = _tenantFieldKey(tenantId, table, oldRootJson);
  var plain  = bCrypto.decryptPacked(packed, oldKey, aad);
  var newKey = _tenantFieldKey(tenantId, table, newRootJson);
  var reSealed = bCrypto.encryptPacked(plain, newKey, aad);
  return TENANT_FIELD_PREFIX + reSealed.toString("base64");
}

function _sealRowForTenant(tenantId, table, row) {
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

function _unsealRowForTenant(ctx, tenantId, table, row) {
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
      catch (e) {
        agentAudit.safeAudit(ctx.audit, "agent.tenant.cross_tenant_decrypt_refused", null, {
          tenantId: tenantId, table: table, field: f,
          reason: (e && e.message) || String(e),
        });
        out[f] = null;
      }
    }
  }
  return out;
}

var REGISTRY_SCHEMA_VERSION = "1";

function _registryAadFor(row) {
  return cryptoField()._aadParts(
    { rowIdField: "tenantId", schemaVersion: REGISTRY_SCHEMA_VERSION },
    SEAL_TABLE, "metadata", row);
}

function _resealRegistry(args) {
  var store = args && args.store;
  validateOpts.requireMethods(store, ["list", "set"],
    "reseal: store for the '" + SEAL_TABLE + "' table",
    AgentTenantError, "agent-tenant/bad-reseal-store");
  validateOpts.requireNonEmptyString(args.oldRootJson,
    "reseal: oldRootJson (b.vault.getKeysJson output)", AgentTenantError, "agent-tenant/bad-reseal-root");
  validateOpts.requireNonEmptyString(args.newRootJson,
    "reseal: newRootJson (b.vault.getKeysJson output)", AgentTenantError, "agent-tenant/bad-reseal-root");
  return Promise.resolve(store.list()).then(function (rows) {
    rows = Array.isArray(rows) ? rows : [];
    var resealed = 0;
    var chain = Promise.resolve();
    rows.forEach(function (row) {
      if (!row || row.tenantId == null) return;
      var cell = row.metadata;
      if (!vaultAad.isAadSealed(cell)) return;
      var aad = _registryAadFor(row);
      var next = vaultAad.resealRoot(cell, aad, args.oldRootJson, args.newRootJson);
      var updated = Object.assign({}, row, { metadata: next });
      resealed += 1;
      chain = chain.then(function () { return store.set(row.tenantId, updated); });
    });
    return chain.then(function () {
      return { table: SEAL_TABLE, resealed: resealed };
    });
  });
}

function _resealTenantCells(args) {
  var store = args && args.store;
  validateOpts.requireMethods(store, ["list", "write"],
    "reseal: store for tnt-v1: cells",
    AgentTenantError, "agent-tenant/bad-reseal-store");
  validateOpts.requireNonEmptyString(args.oldRootJson,
    "reseal: oldRootJson (b.vault.getKeysJson output)", AgentTenantError, "agent-tenant/bad-reseal-root");
  validateOpts.requireNonEmptyString(args.newRootJson,
    "reseal: newRootJson (b.vault.getKeysJson output)", AgentTenantError, "agent-tenant/bad-reseal-root");
  return Promise.resolve(store.list()).then(function (cells) {
    cells = Array.isArray(cells) ? cells : [];
    var resealed = 0;
    var chain = Promise.resolve();
    cells.forEach(function (cell) {
      if (!cell || cell.tenantId == null ||
          typeof cell.table !== "string" || typeof cell.field !== "string") {
        return;
      }
      var value = cell.value;
      if (typeof value !== "string" || value.indexOf(TENANT_FIELD_PREFIX) !== 0) {
        return;
      }
      var next = _resealTenantCell(cell.tenantId, cell.table, cell.field,
        value, args.oldRootJson, args.newRootJson);
      resealed += 1;
      chain = chain.then(function () { return store.write(cell, next); });
    });
    return chain.then(function () {
      return { table: TENANT_FIELD_PREFIX, resealed: resealed };
    });
  });
}

function _checkDestroyPreconditions(args, tenantId) {
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

var AAD_ROTATION = [
  {
    table:         SEAL_TABLE,
    rowIdField:    "tenantId",
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    backend:       "external",
    reseal:        _resealRegistry,
  },
  {
    table:         TENANT_FIELD_PREFIX,
    rowIdField:    "tenantId",
    schemaVersion: "v1",
    backend:       "external",
    reseal:        _resealTenantCells,
  },
];

module.exports = {
  create:                    create,
  derivedKey:                _derivedKey,
  CROSS_TENANT_ADMIN_SCOPE:  CROSS_TENANT_ADMIN_SCOPE,
  AgentTenantError:          AgentTenantError,
  AAD_ROTATION:              AAD_ROTATION,
  guards: {
    tenantId: guardTenantId,
  },
};
