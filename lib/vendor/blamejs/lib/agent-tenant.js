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

// At-rest sealing of the tenant registry row's metadata. The registry
// maps a tenantId to its config; the operator-supplied `metadata` is
// sealed via b.cryptoField before reaching the backend so a DB dump
// does not leak it — when a vault is configured (the default in a
// booted app via b.start). Without a vault there is no key, so the row
// is stored as-is. The registry is framework-owned coordination state,
// so it uses the singleton vault key (cryptoField.sealRow) — the
// per-tenant `sealRowForTenant` path below is for tenant DATA tables
// where cross-tenant cryptographic isolation matters. AAD binds the
// ciphertext to the tenantId (the row identity); `metadata` is an
// object, so it is JSON-serialized before sealing and parsed on read.
// Rows written before sealing landed carry a plain object; unsealRow
// passes a non-sealed value through, so they still read.
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
  if (!vault().isInitialized()) return row;          // vault-less: store as-is (no key)
  _ensureSealTable();
  var pre = Object.assign({}, row);
  if (pre.metadata !== undefined && pre.metadata !== null && typeof pre.metadata !== "string") {
    pre.metadata = safeJson.stringify(pre.metadata);
  }
  return cryptoField().sealRow(SEAL_TABLE, pre);
}
function _unsealMetadata(row) {
  if (!row) return row;
  if (!vault().isInitialized()) return row;          // vault-less: row is plain
  _ensureSealTable();
  var out = cryptoField().unsealRow(SEAL_TABLE, row);
  if (typeof out.metadata === "string") {
    try { out.metadata = safeJson.parse(out.metadata, { maxBytes: SEAL_METADATA_MAX_BYTES }); }
    catch (_e) { /* legacy raw-string metadata — leave as-is */ }
  }
  return out;
}

var CROSS_TENANT_ADMIN_SCOPE = "framework-cross-tenant-admin";

// Per-tenant key derivation domain separators. NIST SP 800-108 r1 §5.1
// KDF-in-Counter shape — fixed "label" + tenantId-as-salt + purpose-as-
// info. The root secret is the vault master keypair (SHA3-512 of
// b.vault.getKeysJson()); rotating the vault keypair changes the root,
// so every tnt-v1: cell sealed under the old root must be re-sealed
// under the new root. That migration is NOT automatic — it runs via the
// AAD_ROTATION reseal hook (see `reseal` below), which the vault-key
// rotation pipeline composes per the explicit-root primitive contract.
var TENANT_KDF_LABEL = "blamejs.agent.tenant/v1";
// 32 bytes — XChaCha20-Poly1305 key length. Distinct from the audit
// truncation buffer so future key-length bumps don't have to chase a
// magic constant.
var TENANT_KEY_BYTES = 32;                                                                              // XChaCha20-Poly1305 key length (256 bits)

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
    // Serializes register/unregister per tenantId so a concurrent pair for the
    // same tenant can't interleave the check-then-create (await get ->
    // throw-if-exists -> await set) and both write — a duplicate-create /
    // lost-registration. In process only; a shared persistent backend also
    // needs its own uniqueness constraint.
    registrySerializer: safeAsync.keyedSerializer(),
    // Archived tenants — keys retained but no live config; restore
    // requires explicit operator opt-in.
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
  // Seal metadata at rest (tenantId is populated, so the AAD binding
  // resolves). The plaintext `row` is kept for the audit below.
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
  // Archive default — retain the key + metadata for retention-mandated
  // restoration. Operator's compliance regime drives archivePolicy.
  // Persist as a `status: "archived"` row in the same
  // backend rather than only the process-local Map. GDPR Art. 17 +
  // HIPAA §164.530(j) require the archived state to survive process
  // restart (auditor pulls a deleted tenant's archival record years
  // later); a Map-only archive evaporated on every redeploy.
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
  // Two-phase: persist the archived row first, then delete the live
  // row. If the persist fails, the live row stays and the operator
  // can retry; the inverse (delete-then-persist) loses the row on
  // a backend hiccup. Operators wiring a durable backend get
  // restart-survival for free.
  if (typeof ctx.backend.archive === "function") {
    await ctx.backend.archive(tenantId, archivedRow);
  } else {
    // Backends without a dedicated archive() API store the archived
    // row under a sentinel-prefixed key so list() can find it and
    // lookup() (which checks status) refuses live-row access.
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
    // Skip archived rows from the live list; listArchived surfaces
    // them separately. Backends without an `archive()` API stored the
    // archived row under "__archived__/<tenantId>" via the fallback;
    // the row's status === "archived" sentinel is the canonical
    // discriminator regardless of backend.
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
  // Prefer the operator's `listArchived()` when available — durable
  // backends that need an index can implement it cheaper than walking
  // every row. Fall back to scanning list() for `status: "archived"`
  // rows (the in-memory + sentinel-prefix path).
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
  // Process-local cache (set on archive() in this process) for the
  // common case of `archive→listArchived` within one boot before the
  // backend list() index catches up.
  ctx.archive.forEach(function (v) {
    var found = false;
    for (var k = 0; k < out.length; k += 1) {
      if (out[k].tenantId === v.tenantId) { found = true; break; }
    }
    if (!found) out.push({ tenantId: v.tenantId, archivedAt: v.archivedAt, policy: v.policy });
  });
  return out;
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
//
// `namespaceHash(label, tenantId)` is a PUBLIC function
// over PUBLIC inputs; an attacker who learns `tenantId` (an account id
// surfaced in URLs / API responses) reconstructs every per-tenant key
// without any secret material. The defense the docstring promises —
// "cross-tenant decrypt refused at the vault boundary" — never bound
// to anything secret.
//
// NIST SP 800-108 r1 §5.1 (KDF in Counter / Feedback Mode): a key
// derivation function MUST consume a secret KDK (Key Derivation Key)
// alongside the public label + context. GDPR Art. 32 (Security of
// processing) requires "the pseudonymisation and encryption of
// personal data" — keys derived purely from public per-record
// identifiers are pseudonymisation-only, not encryption.
//
// New shape: SHAKE256(label || rootKey || tenantId || purpose), where
// rootKey is SHA3-512(vault.getKeysJson()). Same derivation `b.vault.aad`
// uses internally — the vault's master keypair PEM is the secret KDK.
// Rotating the vault passphrase / keypair (b.vaultRotate.rotate)
// changes rootKey, which changes every derived tenant key — so every
// prior tnt-v1: cell must be re-sealed old-root -> new-root. The
// `reseal` hook below (eager-registered via AAD_ROTATION) performs that
// migration; it uses the explicit-root variant of the tenant-key
// derivation (rootKeysJson arg) to decrypt under the old root and
// re-encrypt under the new one within one process.
//
// `derivedKey` returns a hex-encoded 32-byte key (64 chars) to keep
// the wire shape compatible with prior callers. Internal callers that
// need the raw key use `_tenantFieldKey` directly.

function _vaultRootBytes(rootKeysJson) {
  // rootKeysJson lets the vault-key rotation pipeline derive the per-
  // tenant key under a SPECIFIC vault root (old or new keypair) within
  // one process — mirrors vault-aad._deriveKey's explicit-root arg. When
  // omitted it reads the live singleton via vault().getKeysJson().
  //
  // getKeysJson() throws when the vault hasn't been init'd. That is the
  // right secure-by-default posture: tenant-derived keys cannot be
  // produced before the operator has bootstrapped the vault. The error
  // reaches the caller (sealField / register) so an operator mis-ordering
  // boot (start agents before vault.init) sees a clear refusal rather
  // than getting weakened-but-deterministic keys.
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
  // Domain-separated KDF input. NUL separators between fields prevent
  // (label, tenantId="x\0y", purpose="z") colliding with
  // (label, tenantId="x", purpose="y\0z") — same byte concatenation,
  // different logical context. rootKeysJson (optional) pins the vault
  // root for the rotation reseal path; default is the live singleton.
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
  // Public API — returns hex so the existing wire shape (operators
  // storing the derived key string in their DB) is unchanged. Internal
  // AEAD callers use `_deriveTenantKeyBytes` directly to skip the
  // hex/Buffer round-trip.
  return _deriveTenantKeyBytes(tenantId, purpose).toString("hex");
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

function _tenantFieldKey(tenantId, table, rootKeysJson) {
  // 32-byte symmetric key for XChaCha20-Poly1305. _deriveTenantKeyBytes
  // returns the raw key bound to the vault master + tenantId + purpose
  // — see the commentary above _derivedKey for the threat
  // model that drove this away from public-input-only derivation.
  // rootKeysJson (optional) pins a specific vault root for the rotation
  // reseal path; default is the live singleton.
  return _deriveTenantKeyBytes(tenantId, "cryptoField:" + table, rootKeysJson);
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

// Explicit-root re-seal of a single tnt-v1: cell, old root -> new root,
// under the SAME (tenantId, table, field) AAD. Decrypts with the key
// derived from oldRootJson and re-encrypts under newRootJson — the
// XChaCha20-Poly1305 tag refuses any cell that wasn't sealed under the
// old root + this AAD (CWE-345 / CWE-441). Values without the prefix
// (plaintext columns, already-rotated cells) pass through untouched.
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
        // Null-on-decrypt-failure was silent; the docstring
        // promised "audit chain surfaces the failure" but no emit ever
        // ran. Cross-tenant ciphertext replay / tampered row / wrong-
        // prefix all hit this path; operator audit pipelines need the
        // signal to alert. CWE-778 (Insufficient Logging) — defense-
        // in-depth that the field nulled silently.
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

// ---- Vault-key rotation: re-seal hook -------------------------------------
//
// Two root-derived families live in this module, both keyed off the vault
// master keypair (SHA3-512 of b.vault.getKeysJson()):
//
//   1. The registry table "agent_tenant_registry" — a b.cryptoField
//      {aad:true} table whose `metadata` column holds vault.aad: cells.
//      Re-sealed old-root -> new-root via vaultAad.resealRoot, with the
//      AAD tuple rebuilt by cryptoField._aadParts (the SAME builder the
//      seal side uses — single source of truth, no drift).
//
//   2. The tnt-v1: per-tenant sealed cells written by sealField /
//      sealRowForTenant. Re-sealed via _resealTenantCell, which derives
//      the per-tenant XChaCha20-Poly1305 key under each root explicitly
//      and re-binds the (tenantId|table|field) AAD.
//
// Both descriptors export a `reseal({ store, oldRootJson, newRootJson })`
// hook. The vault-key rotation pipeline eager-registers every module's
// AAD_ROTATION descriptor(s) and calls each reseal with the operator-
// supplied backing store; without this hook, a keypair rotation would
// orphan every prior cell (decryptable under neither root). oldRootJson /
// newRootJson are b.vault.getKeysJson() output for the two keypairs.

var REGISTRY_SCHEMA_VERSION = "1";

// Rebuild the registry's AAD tuple via the cryptoField seal-side builder
// so the rotate side can never drift from the seal side. The schema
// shape cryptoField._aadParts reads is { rowIdField, schemaVersion }.
function _registryAadFor(row) {
  return cryptoField()._aadParts(
    { rowIdField: "tenantId", schemaVersion: REGISTRY_SCHEMA_VERSION },
    SEAL_TABLE, "metadata", row);
}

// Re-seal the registry table's vault.aad: metadata cells. `store` is the
// operator's backing store for SEAL_TABLE, exposing list() ->
// [{ tenantId, metadata, ... }] and set(tenantId, row). Each metadata
// cell that is vault.aad-sealed is re-sealed old-root -> new-root under
// the SAME (table, tenantId, "metadata", schemaVersion) AAD.
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
      if (!vaultAad.isAadSealed(cell)) return;   // plaintext / already-migrated
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

// Re-seal the tnt-v1: per-tenant sealed cells. `store` is the operator's
// backing store for every table that carries tnt-v1: columns, exposing
// list() -> [{ tenantId, table, field, value, _id? }] (one entry per
// sealed cell, carrying the context needed to rebuild AAD + key) and
// write(cell, newValue) to persist the re-sealed value. Plaintext /
// already-rotated values pass through untouched.
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
        return;   // not a tnt-v1: cell — leave untouched
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

// Vault-key rotation descriptors — the rotation pipeline eager-registers
// these and calls each reseal({ store, oldRootJson, newRootJson }) to
// re-seal this module's two root-derived families old-root -> new-root.
// backend: "external" — the cells live in the operator's backing store
// (the registry backend + the operator's tenant data tables), not in the
// framework's at-rest SQLite, so the rotation pipeline cannot walk them
// from the data directory alone; the operator supplies the store.
var AAD_ROTATION = [
  {
    table:         SEAL_TABLE,
    rowIdField:    "tenantId",
    schemaVersion: REGISTRY_SCHEMA_VERSION,
    backend:       "external",
    reseal:        _resealRegistry,
  },
  {
    table:         TENANT_FIELD_PREFIX,   // prefix family, not a single SQL table
    rowIdField:    "tenantId",
    schemaVersion: "v1",                  // tnt-v1: ciphertext shape version
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
