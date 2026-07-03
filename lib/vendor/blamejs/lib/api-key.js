// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.apiKey
 * @nav    Identity
 * @title  API Keys
 *
 * @intro
 *   Long-lived API token primitives — generate / verify / revoke /
 *   rotate; sealed at rest; per-key scope + rate-limit. Tokens are
 *   Stripe-style prefix-recognizable strings of the form
 *   `<prefix>_<namespace>_<idHex>_<secretHex>` so a leaked credential
 *   is identifiable on sight (secret-scanner allowlists, log-grep
 *   for `bk_live_`).
 *
 *   Storage: framework table `_blamejs_api_keys` with sealed columns
 *   (ownerId / scopes / metadata via cryptoField), `ownerIdHash` for
 *   indexed `listForOwner`. Same dual-storage pattern as sessions —
 *   local SQLite in single-node mode, external-db in cluster mode,
 *   dispatched via cluster-storage. Hash algorithm is operator-
 *   selectable (SHAKE256 default for high-entropy random secrets;
 *   Argon2id available for low-entropy deployments). Visibility
 *   defaults are ON: `auditFailures`, `auditSuccess`, and
 *   `trackLastUsedAt` all default true so HIPAA §164.312(b) /
 *   PCI-DSS 10.2.1 / GDPR Art. 32 trails are complete out of the
 *   box. Operators with extreme verify-rate volume opt OUT
 *   explicitly.
 *
 *   Graceful rotation moves the prior secret hash into a
 *   `secondarySecretHash` slot with a TTL (default 7 days) so
 *   in-flight clients survive the rotation window without coordinated
 *   redeploy.
 *
 * @card
 *   Long-lived API token primitives — generate / verify / revoke / rotate; sealed at rest; per-key scope + rate-limit.
 */

var bCrypto = require("./crypto");
var credentialHash = require("./credential-hash");
var safeJson = require("./safe-json");
var lazyRequire = require("./lazy-require");
var clusterStorage = require("./cluster-storage");
var cluster = require("./cluster");
var cryptoField = require("./crypto-field");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var sql = require("./sql");
var C = require("./constants");
var numericChecks = require("./numeric-checks");
var { ApiKeyError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

var _err = ApiKeyError.factory;

// Logical framework table name. Self-mapped in LOCAL_TO_EXTERNAL, so it is
// passed BARE to b.sql: clusterStorage.execute rewrites it to the configured
// prefix and placeholderizes the `?` markers, so one query text runs against
// the local SQLite single-node backend and the operator's external DB in
// cluster mode.
var TABLE   = "_blamejs_api_keys";   // allow:hand-rolled-sql — bare logical name, passed to b.sql for clusterStorage rewrite

// b.sql opts for every _blamejs_api_keys statement: thread the ACTIVE backend
// dialect (clusterStorage.dialect() — "sqlite" single-node, "postgres" |
// "mysql" in cluster mode) so the emitted identifier quoting + dialect idioms
// match the backend the SQL dispatches to. Defaulting to "sqlite" works on
// Postgres only by accident (both double-quote identifiers) and emits the
// wrong quoting on MySQL, so this is the canonical resolver threaded into
// b.sql. clusterStorage.execute still rewrites the bare table name +
// translates `?` placeholders at dispatch; this controls only the builder-
// side quoting + idiom selection. The table name stays BARE (no quoteName)
// so clusterStorage's prefix rewrite still fires.
function _sqlOpts() { return { dialect: clusterStorage.dialect() }; }

// Column order used for INSERT — kept as a constant so the column list and
// the row object stay in sync. Must match _blamejs_api_keys' schema in
// db.js (single-node) and framework-schema.js (cluster mode).
var COLS = [
  "id", "namespace", "ownerId", "ownerIdHash", "secretHash",
  "secondarySecretHash", "secondaryExpiresAt",
  "scopes", "metadata", "createdAt", "expiresAt", "revokedAt",
  "lastUsedAt", "prefix",
];

// Default rotate grace period when caller passes { graceful: true }
// without an explicit gracePeriodMs. 7 days is enough to migrate the
// vast majority of clients without paging anyone, short enough that
// a forgotten old secret stops working before it becomes a long-tail
// liability.
var DEFAULT_ROTATE_GRACE_MS = C.TIME.days(7);

// Visibility defaults are ON. When an operator wires `audit: b.audit`,
// they're declaring "I want to know what happens with these credentials"
// — that includes verify success (every access to a credential), reads
// (listForOwner/getById), and all state changes. The compliance trail
// (HIPAA §164.312(b), PCI-DSS 10.2.1, GDPR Art. 32) needs WHO + WHAT +
// WHEN on every access, not just on writes.
//
// Operators with extreme verify-rate volume opt OUT explicitly via
// `auditSuccess: false`. Failures stay on regardless.
var DEFAULTS = Object.freeze({
  prefix:           "bk",
  idBytes:          C.BYTES.bytes(8),    // 16 hex chars
  secretBytes:      C.BYTES.bytes(16),   // 32 hex chars
  trackLastUsedAt:  true,     // visibility on dormant / leaked keys
  auditFailures:    true,     // failure events are actionable signals
  auditSuccess:     true,     // compliance trail — opt out at extreme volume
  purgeAfterMs:     C.TIME.days(90),
  // Credential hash algorithm for new issues. Falls through to
  // credentialHash defaults; SHAKE256 is the active per-framework
  // because api-key secrets are 128-bit random (memory-hard property
  // buys nothing at that entropy) and SHAKE256 is an XOF — the
  // envelope payload length itself drives the digest size, so a
  // future operator can request 96-byte digests without an algorithm
  // rotation. Operators with low-entropy or paranoia-mode storage
  // pin "argon2id" per registry. The envelope ensures historical
  // credentials always remain verifiable.
  hashAlgo:         "shake256",
});

// ---- Config-time validation helpers (throw on bad input) ----

var _isPositiveInt = numericChecks.isPositiveInt;

function _validateIdentifier(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    throw _err("BAD_OPT", name + " must be a non-empty string, got " + typeof value);
  }
  if (/[_\s]/.test(value)) {
    throw _err("BAD_OPT", name + " must not contain underscores or whitespace (collides with format separator), got " +
      JSON.stringify(value));
  }
}

function _validateCreateOpts(opts) {
  validateOpts.shape(opts, {
    namespace:       function (v, l) { _validateIdentifier(l, v); },
    prefix:          function (v, l) { if (v !== undefined) _validateIdentifier(l, v); },
    idBytes:         "optional-positive-int",
    secretBytes:     "optional-positive-int",
    trackLastUsedAt: "optional-boolean",
    auditFailures:   "optional-boolean",
    auditSuccess:    "optional-boolean",
    purgeAfterMs:    "optional-non-negative",
    hashAlgo:        function (v) {
      if (v !== undefined) {
        if (typeof v !== "string" || (v !== "shake256" && v !== "argon2id")) {
          throw _err("BAD_OPT", "apiKey.create: hashAlgo must be 'shake256' or 'argon2id', got " +
            JSON.stringify(v));
        }
      }
    },
    audit:           function (v) { validateOpts.auditShape(v, "apiKey.create", ApiKeyError); },
    clock:           "optional-function",
  }, "apiKey.create", ApiKeyError);
}

function _validateIssueOpts(opts) {
  validateOpts.shape(opts, {
    ownerId:   { rule: "required-string",       code: "MISSING_OWNER" },
    scopes:    { rule: "optional-string-array", code: "BAD_SCOPES" },
    metadata:  { rule: "optional-plain-object", code: "BAD_METADATA" },
    expiresAt: function (v) {
      if (v !== undefined && v !== null) {
        if (typeof v !== "number" || !isFinite(v) || v < 0) {
          throw _err("BAD_OPT", "apiKey.issue: expiresAt must be a non-negative finite number (unix ms) or null");
        }
      }
    },
  }, "apiKey.issue", ApiKeyError, undefined, {
    // `req` / `context` are the audit-actor pass-through bag — forwarded
    // verbatim to requestHelpers.resolveActorWithOverride (via _actor)
    // to populate the issue audit's 5 W's, not validated locally.
    allow: ["req", "context"],
  });
}

// ---- Token format ----

// Format: <prefix>_<namespace>_<idHex>_<secretHex>
// Each part is alphanumeric so split-by-underscore is unambiguous as long
// as prefix/namespace are validated to contain no underscores. We verify
// that during create.

/**
 * @primitive b.apiKey.parseFormat
 * @signature b.apiKey.parseFormat(token)
 * @since     0.4.9
 * @status    stable
 * @related   b.apiKey.create
 *
 * Pure parser for the framework's `<prefix>_<namespace>_<idHex>_<secretHex>`
 * token format. Returns `{ prefix, namespace, idHex, secretHex }` on
 * a structurally-valid token, `null` otherwise. Never touches the
 * registry — used by routing code that wants to dispatch a request
 * to the correct registry (multi-namespace deployments) before
 * calling `verify()`. Hex parts are not constant-time-compared here;
 * that happens inside `verify()` against the stored hash.
 *
 * @example
 *   var parts = b.apiKey.parseFormat("bk_live_<id-hex>_<secret-hex>");
 *   // → { prefix: "bk", namespace: "live", idHex: "<id-hex>",
 *   //     secretHex: "<secret-hex>" }
 *
 *   b.apiKey.parseFormat("not-a-token");          // → null
 *   b.apiKey.parseFormat("bk_live_xyz_zzz");      // → null (non-hex)
 */
function parseFormat(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  var parts = token.split("_");
  if (parts.length !== 4) return null;
  var prefix = parts[0], ns = parts[1], idHex = parts[2], secretHex = parts[3];
  if (!prefix || !ns || !idHex || !secretHex) return null;
  if (!/^[0-9a-f]+$/i.test(idHex) || !/^[0-9a-f]+$/i.test(secretHex)) return null;
  return { prefix: prefix, namespace: ns, idHex: idHex, secretHex: secretHex };
}

function _composeKey(prefix, namespace, idHex, secretHex) {
  return prefix + "_" + namespace + "_" + idHex + "_" + secretHex;
}

function _composedId(namespace, idHex) {
  return namespace + ":" + idHex;
}

// ---- Sealed-row helpers ----

function _sealForInsert(row) {
  var sealed = cryptoField.sealRow(TABLE, row);
  for (var i = 0; i < COLS.length; i++) {
    if (!(COLS[i] in sealed)) sealed[COLS[i]] = null;
  }
  return sealed;
}

// ---- Registry factory ----

/**
 * @primitive b.apiKey.create
 * @signature b.apiKey.create(opts)
 * @since     0.4.9
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.apiKey.parseFormat, b.permissions.create, b.session
 *
 * Build an API-key registry bound to a single `namespace`. Returns a
 * handle exposing async `issue` / `verify` / `revoke` / `rotate` /
 * `listForOwner` / `getById` / `purgeExpired`. State changes
 * (`issue` / `revoke` / `rotate` / `purgeExpired`) require leader in
 * cluster mode; reads (`verify` / `getById` / `listForOwner`) run on
 * any node. Issued tokens contain the secret material exactly once —
 * the registry persists only the SHAKE256 / Argon2id hash and a
 * scrub-safe record without secrets. Operators with multiple key
 * lifecycles (e.g. `live` / `test`) instantiate one registry per
 * namespace.
 *
 * @opts
 *   namespace:        string,            // registry namespace (required, no underscores / whitespace)
 *   prefix:           string,            // token prefix (default "bk", no underscores)
 *   idBytes:          number,            // bytes of id randomness (default 8 → 16 hex chars)
 *   secretBytes:      number,            // bytes of secret randomness (default 16 → 32 hex chars)
 *   trackLastUsedAt:  boolean,           // update lastUsedAt on verify success (default true)
 *   auditFailures:    boolean,           // emit verify-failure audits (default true)
 *   auditSuccess:     boolean,           // emit verify/list/get-success audits (default true)
 *   purgeAfterMs:     number,            // age threshold for purgeExpired (default 90 days)
 *   hashAlgo:         string,            // "shake256" (default) or "argon2id"
 *   audit:            b.audit,           // optional audit sink
 *   clock:            function,          // () → unix ms (test override)
 *
 * @example
 *   var keys = b.apiKey.create({
 *     namespace: "live",
 *     audit:     b.audit,
 *   });
 *
 *   var issued = await keys.issue({
 *     ownerId:   "user-42",
 *     scopes:    ["read:users", "write:posts"],
 *     metadata:  { name: "Mobile app v3" },
 *     expiresAt: Date.now() + b.constants.TIME.days(90),
 *   });
 *   // issued.key — "bk_live_5b9e7c8a4f2d1e3a_8a7b6c5d4e3f2a1b" (returned ONCE)
 *
 *   var record = await keys.verify(req.headers["x-api-key"]);
 *   if (!record) return res.writeHead(401).end();
 *   // → { id, ownerId, scopes, metadata, lastUsedAt, ... }
 *
 *   // Graceful rotation — old secret keeps working for 7 days:
 *   var rotated = await keys.rotate(issued.id, { graceful: true });
 *
 *   await keys.revoke(issued.id);                  // immediate cutover
 *   var owned = await keys.listForOwner("user-42");
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "prefix", "idBytes", "secretBytes",
    "trackLastUsedAt", "auditFailures", "auditSuccess",
    "purgeAfterMs", "hashAlgo", "audit", "clock",
  ], "apiKey");
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var prefix          = cfg.prefix;
  var namespace       = opts.namespace;
  var idBytes         = cfg.idBytes;
  var secretBytes     = cfg.secretBytes;
  var trackLastUsedAt = cfg.trackLastUsedAt;
  var auditFailures   = cfg.auditFailures;
  var auditSuccess    = cfg.auditSuccess;
  var purgeAfterMs    = cfg.purgeAfterMs;
  var hashAlgo        = cfg.hashAlgo;
  var audit           = opts.audit || null;
  var clock           = opts.clock || function () { return Date.now(); };

  var _emit = validateOpts.makeAuditEmitter(audit);

  // Build the audit actor by extracting the 5 W's from the supplied
  // request (WHO/WHERE/HOW), then layering caller-supplied context
  // and an explicit userId on top so the most specific value wins.
  // The audit chain treats null fields as "unknown", so partial
  // context is always safe.
  function _actor(callerOpts, userId) {
    return requestHelpers.resolveActorWithOverride(
      callerOpts,
      userId ? { userId: userId } : null
    );
  }

  // Fresh SELECT builder over the full column set. BARE logical table name
  // (_blamejs_api_keys) — clusterStorage rewrites it to the configured
  // prefix and placeholderizes. Callers chain the WHERE family + .toSql().
  function _selectBuilder() {
    return sql.select(TABLE, _sqlOpts()).columns(COLS);   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
  }

  function _scrubRecord(row) {
    if (!row) return null;
    var unsealed = cryptoField.unsealRow(TABLE, row);
    var scopes = null;
    if (unsealed.scopes) {
      try { scopes = safeJson.parse(unsealed.scopes); } catch (_e) { scopes = null; }
    }
    var metadata = null;
    if (unsealed.metadata) {
      try { metadata = safeJson.parse(unsealed.metadata); } catch (_e) { metadata = null; }
    }
    var idParts = String(unsealed.id).split(":");
    var idHexOnly = idParts.length === 2 ? idParts[1] : unsealed.id;
    return {
      id:                  idHexOnly,
      namespace:           unsealed.namespace,
      ownerId:             unsealed.ownerId,
      scopes:              scopes || [],
      metadata:            metadata || null,
      createdAt:           Number(unsealed.createdAt),
      expiresAt:           unsealed.expiresAt == null ? null : Number(unsealed.expiresAt),
      revokedAt:           unsealed.revokedAt == null ? null : Number(unsealed.revokedAt),
      lastUsedAt:          unsealed.lastUsedAt == null ? null : Number(unsealed.lastUsedAt),
      // secondaryExpiresAt is operator-visible signal that a graceful
      // rotation is in flight; secondarySecretHash itself is NEVER
      // exposed.
      secondaryExpiresAt:  unsealed.secondaryExpiresAt == null ? null : Number(unsealed.secondaryExpiresAt),
      prefix:              unsealed.prefix,
    };
  }

  async function issue(issueOpts) {
    cluster.requireLeader();
    _validateIssueOpts(issueOpts);
    var idHex     = bCrypto.generateToken(idBytes);
    var secretHex = bCrypto.generateToken(secretBytes);
    var compositeId = _composedId(namespace, idHex);
    var nowMs     = clock();
    var scopes    = issueOpts.scopes || [];
    var metadata  = issueOpts.metadata || null;
    var expiresAt = (issueOpts.expiresAt === undefined) ? null : issueOpts.expiresAt;

    var secretEnvelope = await credentialHash.hash(secretHex, { algo: hashAlgo });
    var sealed = _sealForInsert({
      id:                  compositeId,
      namespace:           namespace,
      ownerId:             issueOpts.ownerId,
      secretHash:          secretEnvelope,
      secondarySecretHash: null,
      secondaryExpiresAt:  null,
      scopes:              JSON.stringify(scopes),
      metadata:            metadata ? JSON.stringify(metadata) : null,
      createdAt:           nowMs,
      expiresAt:           expiresAt,
      revokedAt:           null,
      lastUsedAt:          null,
      prefix:              prefix,
    });
    var insertRow = {};
    for (var ci = 0; ci < COLS.length; ci++) insertRow[COLS[ci]] = sealed[COLS[ci]];
    var insertBuilt = sql.insert(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
      .columns(COLS)
      .values(insertRow)
      .toSql();
    await clusterStorage.execute(insertBuilt.sql, insertBuilt.params);

    _emit("apikey.issue", {
      actor:    _actor(issueOpts, issueOpts.ownerId),
      resource: { kind: "apikey", id: compositeId },
      metadata: { namespace: namespace, scopes: scopes, expiresAt: expiresAt },
    });
    _emitEvent("apikey.issue", 1, { namespace: namespace });

    return {
      id:        idHex,
      secret:    secretHex,
      key:       _composeKey(prefix, namespace, idHex, secretHex),
      scopes:    scopes,
      metadata:  metadata,
      createdAt: nowMs,
      expiresAt: expiresAt,
    };
  }

  async function verify(token, verifyOpts) {
    var parsed = parseFormat(token);
    if (!parsed) return null;
    if (parsed.prefix !== prefix || parsed.namespace !== namespace) return null;

    var compositeId = _composedId(namespace, parsed.idHex);
    var verifyBuilt = _selectBuilder().where("id", compositeId).toSql();
    var row = await clusterStorage.executeOne(verifyBuilt.sql, verifyBuilt.params);
    if (!row) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure",
          reason:   "not-found",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "not-found" });
      return null;
    }

    var nowMs = clock();
    var rowOwnerId = null;
    try {
      var unsealedOwner = cryptoField.unsealRow(TABLE, row);
      rowOwnerId = unsealedOwner.ownerId;
    } catch (_e) { rowOwnerId = null; }

    if (row.revokedAt != null) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "revoked",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "revoked" });
      return null;
    }
    if (row.expiresAt != null && Number(row.expiresAt) < nowMs) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "expired",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "expired" });
      return null;
    }

    // Hash dispatch goes through credentialHash so the persisted byte
    // controls the verification algorithm. Both primary and secondary
    // (graceful-rotation) slots are envelope-encoded.
    var primaryMatch = await credentialHash.verify(parsed.secretHex, row.secretHash);
    var secondaryMatch = false;
    var secondaryActive = row.secondarySecretHash != null &&
                          row.secondaryExpiresAt != null &&
                          Number(row.secondaryExpiresAt) >= nowMs;
    if (!primaryMatch && secondaryActive) {
      secondaryMatch = await credentialHash.verify(parsed.secretHex, row.secondarySecretHash);
    }
    if (!primaryMatch && !secondaryMatch) {
      if (auditFailures) {
        _emit("apikey.verify", {
          actor:    _actor(verifyOpts, rowOwnerId),
          resource: { kind: "apikey", id: compositeId },
          outcome:  "failure", reason: "bad-secret",
        });
      }
      _emitEvent("apikey.verify", 1, { namespace: namespace, outcome: "failure", reason: "bad-secret" });
      return null;
    }

    // Leader-gated best-effort writes on a successful verify: bump
    // lastUsedAt when tracked, and transparently re-hash the stored secret
    // when its envelope no longer matches the active algorithm — the
    // rotate-on-next-verify that credentialHash documents but, until now,
    // no consumer wired. Primary match only: the secondary (graceful-
    // rotation) slot is not the active secret, so it must not overwrite
    // secretHash. The whole block is best-effort — the credential already
    // verified under the stored hash and stays valid even if the write
    // fails; the row re-upgrades on the next leader verify.
    if (cluster.isLeader()) {
      var touchFields = trackLastUsedAt ? { lastUsedAt: nowMs } : null;
      var didRehash = false;
      if (primaryMatch && credentialHash.needsRehash(row.secretHash, { algo: hashAlgo })) {
        try {
          var freshSecretHash = await credentialHash.hash(parsed.secretHex, { algo: hashAlgo });
          touchFields = touchFields || {};
          touchFields.secretHash = freshSecretHash;
          didRehash = true;
        } catch (_e) { /* re-hash is best-effort; verify success stands */ }
      }
      if (touchFields) {
        try {
          var touchQb = sql.update(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
            .set(touchFields)
            .where("id", compositeId);
          if (didRehash) {
            // Compare-and-swap on the exact hash we verified against: only land
            // the re-hash if the stored primary is STILL that value. A verify
            // that races rotate()/hardRotate (which already installed a new
            // secretHash) must not clobber the rotated secret back to the old
            // one — the predicate then matches no rows and the upgrade no-ops,
            // which is correct because the row is already on a fresh hash.
            touchQb.where("secretHash", row.secretHash);
          }
          var touchBuilt = touchQb.toSql();
          var touchResult = await clusterStorage.execute(touchBuilt.sql, touchBuilt.params);
          // Only record the migration when the CAS actually swapped a row (a
          // rowCount of 0 means a concurrent rotation won the race).
          if (didRehash && !(touchResult && touchResult.rowCount === 0)) {
            _emitEvent("apikey.secret_rehash", 1, { namespace: namespace, algo: hashAlgo });
            _emit("apikey.secret_rehash", {
              actor:    _actor(verifyOpts, rowOwnerId),
              resource: { kind: "apikey", id: compositeId },
              outcome:  "success",
              metadata: { algo: hashAlgo },
            });
          }
        } catch (_e) { /* best-effort; verify success not blocked by the write */ }
      }
    }

    if (auditSuccess) {
      _emit("apikey.verify", {
        actor:    _actor(verifyOpts, rowOwnerId),
        resource: { kind: "apikey", id: compositeId },
        outcome:  "success",
        metadata: { secondary: secondaryMatch },
      });
    }
    _emitEvent("apikey.verify", 1,
      { namespace: namespace, outcome: "success", secondary: secondaryMatch });
    var record = _scrubRecord(row);
    record.usedSecondary = secondaryMatch;       // operator can detect grace-period usage
    return record;
  }

  async function revoke(idHex, revokeOpts) {
    cluster.requireLeader();
    if (typeof idHex !== "string" || idHex.length === 0) return false;
    var compositeId = _composedId(namespace, idHex);
    var nowMs = clock();
    var revokeBuilt = sql.update(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
      .set({ revokedAt: nowMs })
      .where("id", compositeId)
      .whereNull("revokedAt")
      .toSql();
    var result = await clusterStorage.execute(revokeBuilt.sql, revokeBuilt.params);
    var changed = (result.rowCount || 0) > 0;
    if (changed) {
      _emit("apikey.revoke", {
        actor:    _actor(revokeOpts),
        resource: { kind: "apikey", id: compositeId },
      });
      _emitEvent("apikey.revoke", 1, { namespace: namespace });
    }
    return changed;
  }

  async function rotate(idHex, rotateOpts) {
    cluster.requireLeader();
    if (typeof idHex !== "string" || idHex.length === 0) {
      throw _err("BAD_OPT", "apiKey.rotate: id must be a non-empty string");
    }
    rotateOpts = rotateOpts || {};
    // Graceful rotation: the previous hash stays valid in the
    // secondarySecretHash slot until secondaryExpiresAt. Operators
    // pass either { graceful: true } (default DEFAULT_ROTATE_GRACE_MS)
    // or { gracePeriodMs: <ms> } for an explicit window. Without
    // either, rotation is immediate (old secret invalidated) — this
    // preserves the original semantics for callers that explicitly
    // want a hard cutover.
    var gracePeriodMs = 0;
    if (typeof rotateOpts.gracePeriodMs === "number") {
      if (!isFinite(rotateOpts.gracePeriodMs) || rotateOpts.gracePeriodMs < 0) {
        throw _err("BAD_OPT", "apiKey.rotate: gracePeriodMs must be a non-negative finite number");
      }
      gracePeriodMs = rotateOpts.gracePeriodMs;
    } else if (rotateOpts.graceful === true) {
      gracePeriodMs = DEFAULT_ROTATE_GRACE_MS;
    } else if (rotateOpts.graceful !== undefined && rotateOpts.graceful !== false) {
      throw _err("BAD_OPT", "apiKey.rotate: graceful must be a boolean");
    }

    var compositeId = _composedId(namespace, idHex);
    var rotateSelBuilt = _selectBuilder().where("id", compositeId).toSql();
    var existing = await clusterStorage.executeOne(rotateSelBuilt.sql, rotateSelBuilt.params);
    if (!existing) {
      throw _err("NOT_FOUND", "apiKey.rotate: id '" + idHex + "' not found in namespace '" + namespace + "'");
    }
    if (existing.revokedAt != null) {
      throw _err("REVOKED", "apiKey.rotate: id '" + idHex + "' is revoked");
    }
    var newSecretHex = bCrypto.generateToken(secretBytes);
    var newHash = await credentialHash.hash(newSecretHex, { algo: hashAlgo });
    var nowMs = clock();

    if (gracePeriodMs > 0) {
      // Move current hash → secondary slot, install new hash as primary.
      var graceBuilt = sql.update(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
        .set({
          secretHash:          newHash,
          secondarySecretHash: existing.secretHash,
          secondaryExpiresAt:  nowMs + gracePeriodMs,
        })
        .where("id", compositeId)
        .toSql();
      await clusterStorage.execute(graceBuilt.sql, graceBuilt.params);
    } else {
      // Hard cutover — old secret stops working immediately. Clears
      // any prior secondary slot too (bound NULL via the set map).
      var cutoverBuilt = sql.update(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
        .set({
          secretHash:          newHash,
          secondarySecretHash: null,
          secondaryExpiresAt:  null,
        })
        .where("id", compositeId)
        .toSql();
      await clusterStorage.execute(cutoverBuilt.sql, cutoverBuilt.params);
    }

    _emit("apikey.rotate", {
      actor:    _actor(rotateOpts),
      resource: { kind: "apikey", id: compositeId },
      metadata: { gracePeriodMs: gracePeriodMs },
    });
    _emitEvent("apikey.rotate", 1, { namespace: namespace, graceful: gracePeriodMs > 0 });
    return {
      key:                _composeKey(prefix, namespace, idHex, newSecretHex),
      secret:             newSecretHex,
      secretHash:         newHash,
      gracePeriodMs:      gracePeriodMs,
      secondaryExpiresAt: gracePeriodMs > 0 ? (nowMs + gracePeriodMs) : null,
    };
  }

  async function listForOwner(ownerId, listOpts) {
    if (typeof ownerId !== "string" || ownerId.length === 0) {
      throw _err("BAD_OPT", "apiKey.listForOwner: ownerId must be a non-empty string");
    }
    listOpts = listOpts || {};
    var includeRevoked = !!listOpts.includeRevoked;
    var includeExpired = !!listOpts.includeExpired;
    var lookup = cryptoField.lookupHash(TABLE, "ownerId", ownerId);
    if (!lookup) {
      throw _err("MISCONFIGURED",
        TABLE + " schema is missing the ownerIdHash derived hash — framework misconfigured");
    }
    // Dual-read across the keyed-MAC flip: match the active digest AND the
    // legacy salted-sha3 digest a pre-v0.15.0 row carries (whereIn with a
    // single value emits `IN (?)`, equivalent to `=`).
    var ownerHashes = [lookup.value];
    if (lookup.legacyValue != null && lookup.legacyValue !== lookup.value) {
      ownerHashes.push(lookup.legacyValue);
    }
    var listQb = _selectBuilder()
      .where("namespace", namespace)
      .whereIn("ownerIdHash", ownerHashes);
    if (!includeRevoked) listQb.whereNull("revokedAt");
    if (!includeExpired) {
      var nowForExpiry = clock();
      // (expiresAt IS NULL OR expiresAt >= now) — an OR group ANDed onto
      // the chain so the optional clause keeps its own precedence.
      listQb.whereGroup(function (g) {
        g.whereNull("expiresAt").orWhereOp("expiresAt", ">=", nowForExpiry);
      });
    }
    listQb.orderBy("createdAt", "desc");
    var listBuilt = listQb.toSql();
    var rows = await clusterStorage.execute(listBuilt.sql, listBuilt.params);
    var list = (rows.rows || []).map(_scrubRecord);
    _emitEvent("apikey.list", 1, { namespace: namespace, count: list.length });
    // Read-access audit: "who listed whose keys at time T" — gated by
    // auditSuccess so operators with admin tooling that polls heavily
    // can opt out. ownerId is the audit subject; the listed IDs are
    // included in metadata so a compliance auditor can reconstruct
    // exactly which records were observed.
    if (auditSuccess) {
      _emit("apikey.list", {
        actor:    _actor(listOpts),
        resource: { kind: "apikey-namespace", id: namespace },
        metadata: {
          ownerId:    ownerId,
          count:      list.length,
          observedIds: list.map(function (r) { return r.id; }),
          includeRevoked: includeRevoked,
          includeExpired: includeExpired,
        },
      });
    }
    return list;
  }

  async function getById(idHex, getOpts) {
    if (typeof idHex !== "string" || idHex.length === 0) return null;
    var compositeId = _composedId(namespace, idHex);
    var getBuilt = _selectBuilder().where("id", compositeId).toSql();
    var row = await clusterStorage.executeOne(getBuilt.sql, getBuilt.params);
    var record = _scrubRecord(row);
    _emitEvent("apikey.get", 1,
      { namespace: namespace, found: record !== null });
    if (auditSuccess) {
      _emit("apikey.get", {
        actor:    _actor(getOpts),
        resource: { kind: "apikey", id: compositeId },
        metadata: { found: record !== null },
      });
    }
    return record;
  }

  async function purgeExpired(purgeOpts) {
    cluster.requireLeader();
    var threshold = clock() - purgeAfterMs;
    // SELECT-then-DELETE so we can audit the specific IDs being purged.
    // Compliance auditors expect "key X was purged at time T" — a count-
    // only audit is too coarse for forensic reconstruction. Cost is one
    // extra round-trip per purge call which runs on a schedule (not
    // request-rate), so the cost is irrelevant. The purge predicate
    // (namespace match + an OR of the two "past-threshold" age groups) is
    // applied identically to the SELECT and the DELETE via _applyPurgeWhere.
    function _applyPurgeWhere(qb) {
      return qb
        .where("namespace", namespace)
        .whereGroup(function (g) {
          g.whereGroup(function (a) {
            a.whereNotNull("revokedAt").where("revokedAt", "<", threshold);
          }).orWhereGroup(function (b2) {
            b2.whereNotNull("expiresAt").where("expiresAt", "<", threshold);
          });
        });
    }
    var purgeSelBuilt = _applyPurgeWhere(
      sql.select(TABLE, _sqlOpts()).columns(["id"])   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
    ).toSql();
    var idRows = await clusterStorage.execute(purgeSelBuilt.sql, purgeSelBuilt.params);
    var purgedCompositeIds = (idRows.rows || []).map(function (r) { return r.id; });

    if (purgedCompositeIds.length === 0) {
      _emitEvent("apikey.purge", 1, { namespace: namespace, count: 0 });
      return 0;
    }

    var purgeDelBuilt = _applyPurgeWhere(
      sql.delete(TABLE, _sqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
    ).toSql();
    var result = await clusterStorage.execute(purgeDelBuilt.sql, purgeDelBuilt.params);
    var count = result.rowCount || purgedCompositeIds.length;

    _emit("apikey.purge", {
      actor:    _actor(purgeOpts),
      resource: { kind: "apikey-namespace", id: namespace },
      metadata: {
        count: count,
        // Strip the namespace prefix so the audit payload contains
        // bare idHex values consistent with what callers receive
        // from issue/verify/getById.
        purgedIds: purgedCompositeIds.map(function (cid) {
          var parts = cid.split(":");
          return parts.length === 2 ? parts[1] : cid;
        }),
        thresholdMs: threshold,
      },
    });
    _emitEvent("apikey.purge", 1, { namespace: namespace, count: count });
    return count;
  }

  return {
    issue:         issue,
    verify:        verify,
    revoke:        revoke,
    rotate:        rotate,
    listForOwner:  listForOwner,
    getById:       getById,
    purgeExpired:  purgeExpired,
    namespace:     namespace,
    prefix:        prefix,
  };
}

module.exports = {
  create:       create,
  parseFormat:  parseFormat,
  ApiKeyError:  ApiKeyError,
  DEFAULTS:     DEFAULTS,
};
