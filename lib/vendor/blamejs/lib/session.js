// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.session
 * @featured true
 * @nav    Data
 * @title  Session
 *
 * @intro
 *   Server-side session store with idle + absolute timeouts, encrypted
 *   at rest, sealed columns, audit on every login / logout, and
 *   cluster-aware leader gating.
 *
 *   The session id (sid) is a 32-byte random value returned to the
 *   caller once and stored client-side (cookie / authorization header).
 *   The DB primary key is `sha3('bj-session:' || sid)` — the plaintext
 *   sid never lands in the database. DB exfiltration alone cannot
 *   impersonate a session: the attacker would also need the original
 *   sid the user holds. The `data` column is vault-sealed JSON;
 *   `userId` is sealed; `userIdHash` indexes for destroyAllForUser
 *   without unsealing every row.
 *
 *   Idle + absolute timeout enforcement follows OWASP ASVS 5.0 §3.3
 *   and NIST SP 800-63B-4. Defaults: idle 30 minutes, absolute 12
 *   hours. Both shorten the effective lifetime even when the operator
 *   picked a long ttlMs; repeated `touch({ extendBy })` cannot push
 *   `expiresAt` past the absolute ceiling.
 *
 *   Storage placement is mode-driven: single-node lives in the
 *   framework's main DB under `_blamejs_sessions` (baked into db.js's
 *   schema — apps cannot opt out); cluster mode lives in external-db
 *   under the same name. `clusterStorage.execute` routes by
 *   `cluster.isClusterMode()`; this module does not branch on mode.
 *
 *   Cluster posture per blamejs-cluster-spec.md:
 *   `create` / `destroy` / `destroyAllForUser` / `touch` / `rotate` /
 *   `purgeExpired` are leader-only (gated by `cluster.requireLeader`
 *   at call entry); `verify` and `count` run anywhere.
 *
 *   Optional fingerprint binding: pass `{ req, fingerprintFields }` to
 *   `create` and `verify` to bind a session to a stable hash of
 *   client-IP / user-agent / accept-language. Drift produces an audit
 *   event and surfaces as `fingerprintDrift: true`; strict operators
 *   pass `requireFingerprintMatch: true` (or a `maxAnomalyScore`
 *   threshold with a `scorer`) to refuse the session on drift.
 *
 * @card
 *   Server-side session store with idle + absolute timeouts, encrypted at rest, sealed columns, audit on every login / logout, and cluster-aware leader gating.
 */
var audit = require("./audit");
var canonicalJson = require("./canonical-json");
var validateOpts = require("./validate-opts");
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var { generateToken, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var frameworkSchema = require("./framework-schema");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var safeJson = require("./safe-json");
var sql = require("./sql");
var { SessionError } = require("./framework-error");

// vault is initialized at boot before sessions; lazyRequire keeps the
// load order independent of module-import order. Used to seal/unseal
// the cookie-side sid so the wire token is ciphertext rather than
// plaintext (sealed-cookie default since v0.8.61).
var vault = lazyRequire(function () { return require("./vault"); });
// Lazy — b.session.logout composes the Clear-Site-Data header builder; keep it
// out of the boot require graph (no cycle, but session is a low-level primitive).
var clearSiteData = lazyRequire(function () { return require("./middleware/clear-site-data"); });

// Pluggable session-storage backend. Default uses cluster-storage (which
// in turn dispatches to the framework's main DB or external DB). An
// operator can switch to an isolated backend (e.g. an in-memory or
// tmpfs SQLite via `b.session.stores.localDbThin`) so heavy session
// churn doesn't fight the main DB's WAL fsync + at-rest re-encryption
// cycle. Set once at boot via `b.session.useStore(store)`; the store
// must expose `execute(sql, params)` and `executeOne(sql, params)`
// returning the same `{ rowCount, rows? }` / row-or-null shape the
// cluster-storage path returns.
var _store = null;
function _currentStore() { return _store || clusterStorage; }

var _err = SessionError.factory;

var DEFAULT_TTL_MS = C.TIME.days(7);
// Sanity bound: any session that lives longer than this is almost
// certainly a misconfigured Infinity / oversized literal. Keeps
// expiresAt away from epoch overflow + database-int boundary issues.
var MAX_TTL_MS     = C.TIME.days(3650);   // ~10 years

// Idle + absolute timeout defaults per OWASP ASVS 5.0 §3.3 + NIST
// SP 800-63B-4. expiresAt is the operator-set window; idle/absolute
// are independent enforcement floors that shorten the effective
// session lifetime even when the operator picked a long ttlMs.
//
//  - idle: session expires N ms after the last verify() / touch().
//          Default 30 minutes — short enough to defeat session-token
//          theft via short-lived foothold; long enough that a user
//          reading a long article doesn't get logged out.
//  - absolute: session always expires at most N ms after creation,
//          regardless of activity. Default 12 hours — re-auth at
//          least once per shift even on a continuously-active
//          session. Repeated touch() with extendBy cannot push past
//          this ceiling.
var DEFAULT_IDLE_TIMEOUT_MS     = C.TIME.minutes(30);
var DEFAULT_ABSOLUTE_TIMEOUT_MS = C.TIME.hours(12);

function _validateTtl(ttl, where) {
  if (typeof ttl !== "number" || !isFinite(ttl) || ttl <= 0) {
    throw _err("INVALID_ARG",
      where + ": ttlMs must be a positive finite number, got " + JSON.stringify(ttl), true);
  }
  if (ttl > MAX_TTL_MS) {
    throw _err("INVALID_ARG",
      where + ": ttlMs " + ttl + " exceeds maximum " + MAX_TTL_MS + " (~10 years). " +
      "Sessions this long suggest a misconfigured value.", true);
  }
}
var SID_NAMESPACE  = "bj-session:";
// Session ID = 32 random bytes (64 hex chars) — 256-bit entropy floor
// keeps sids unforgeable even before sealed-cookie encryption layers on
// top. Routed through C.BYTES so every byte literal in the file lives
// behind the same helper.
var SID_BYTES      = C.BYTES.bytes(32);

// Logical session-table name. Two uses, deliberately distinct:
//   - As the cryptoField registry key (sealRow / unsealRow / lookupHash),
//     it stays the LOGICAL name — that is the key db.js registers the
//     sealedFields + derivedHashes under, independent of any table prefix.
//   - As the SQL table name, it is resolved through
//     frameworkSchema.tableName(...) so a configured table prefix
//     (b.frameworkSchema.setTablePrefix) is honored. The name is
//     identity-mapped in LOCAL_TO_EXTERNAL, so clusterStorage's
//     resolveTables leaves it untouched at dispatch.
var SESSION_TABLE = "_blamejs_sessions";   // allow:hand-rolled-sql — canonical logical table-name + cryptoField registry key
function _sessionSqlTable() { return frameworkSchema.tableName(SESSION_TABLE); }

// b.sql opts for every session statement: thread the ACTIVE backend dialect
// (clusterStorage.dialect() — "sqlite" single-node, "postgres" | "mysql" in
// cluster mode) so the emitted identifier quoting and dialect idioms match
// the backend the SQL dispatches to. b.sql defaults to "sqlite", which works
// on Postgres only by accident (both double-quote identifiers) and emits the
// wrong quoting + idioms on MySQL. The default store routes through
// clusterStorage, and an operator localDbThin store is single-node sqlite —
// in both single-node cases clusterStorage.dialect() resolves "sqlite", so
// the opts agree with the store the SQL reaches. clusterStorage.execute (the
// default store) still rewrites table names + translates `?` placeholders at
// dispatch; this controls only the builder-side quoting + idiom selection.
function _sessionSqlOpts() { return { dialect: clusterStorage.dialect() }; }

// Per-subject valid-from boundary table. A monotonic epoch (ms) the issuer
// bumps to invalidate every STATELESS self-validating token (sealed cookie
// with no DB row, JWT) minted before the bump: log-out-everywhere, a
// right-to-erasure cutoff, a forced re-auth after a credential change. Token
// readers compare the token's iat against this boundary via check(). Same
// dual-storage shape as _blamejs_sessions — registered in both db.js's
// FRAMEWORK_SCHEMA (single-node SQLite) and framework-schema.js (cluster
// external-db); clusterStorage.execute routes by cluster mode. The subject id
// is hashed before it becomes the PRIMARY KEY, so the plaintext id never lands
// in the table (the same sidHash / userIdHash discipline the sessions table
// follows).
var VALID_FROM_TABLE = "_blamejs_session_valid_from";   // allow:hand-rolled-sql — canonical logical table-name + reserved schema name
var VALID_FROM_SUBJECT_NAMESPACE = "bj-session-valid-from-subject:";
function _validFromSqlTable() { return frameworkSchema.tableName(VALID_FROM_TABLE); }
function _hashSubjectId(subjectId) { return sha3Hash(VALID_FROM_SUBJECT_NAMESPACE + subjectId); }

// Dialect-aware conflict-row references for the monotonic-max upsert in
// bump(). Mirrors rate-limit.js's pattern: the proposed row is EXCLUDED
// (Postgres/SQLite) / VALUES() (MySQL); the existing row is a self-reference.
function _validFromConflictRefs(dialect, table) {
  if (dialect === "mysql") {
    return {
      proposed: function (col) { return "VALUES(`" + col + "`)"; },
      existing: function (col) { return "`" + table + "`.`" + col + "`"; },
    };
  }
  return {
    proposed: function (col) { return "EXCLUDED.\"" + col + "\""; },
    existing: function (col) { return "\"" + table + "\".\"" + col + "\""; },
  };
}

// CREATE TABLE IF NOT EXISTS for the valid-from boundary, matching the
// framework schema in db.js (single-node) / framework-schema.js (cluster mode):
// subjectHash PRIMARY KEY, validFromEpoch + updatedAt NOT NULL. The pluggable
// store is always a dedicated node:sqlite file (b.session.stores.localDbThin —
// see session-stores.js), so the dialect is the literal "sqlite". Used to
// provision the table on demand in a store-backed-only deployment (a
// b.session.useStore consumer that never ran b.db.init(), so the framework db
// — the default home of this table — is not initialized).
function _validFromSchemaSql() {
  return sql.createTable(_validFromSqlTable(), [
    { name: "subjectHash",    type: "text", primaryKey: true },
    { name: "validFromEpoch", type: "int",  notNull: true },
    { name: "updatedAt",      type: "int",  notNull: true },
  ], { dialect: "sqlite" }).sql;
}

// Run a valid-from boundary operation (bump write / validFrom read / check
// read) against the correct backend. The boundary lives in the FRAMEWORK db
// (clusterStorage) — it is a stateless-token revocation primitive shared across
// every issuer, not per-session data — so that is always the first choice and a
// present db is never silently bypassed. ONLY when the framework db is not
// initialized (single-node, b.db.init() never awaited) AND an operator store is
// configured (b.session.useStore) does the boundary fall back to that store, so
// a store-backed-only deployment's logout-everywhere still raises (and honors)
// the stateless boundary instead of 500ing on db/not-initialized (#340). With
// neither a framework db nor a store, db/not-initialized is a real
// misconfiguration and propagates unchanged (fail closed — the boundary is
// never silently dropped). The store provisions the table on demand because a
// session-data store (localDbThin) does not ship the valid-from DDL.
async function _runValidFrom(runner) {
  try {
    return await runner(clusterStorage);
  } catch (e) {
    if (e && e.code === "db/not-initialized" && _store) {
      // Framework db absent, operator store present: route through the store,
      // provisioning the boundary table first (idempotent CREATE IF NOT EXISTS).
      await _store.execute(_validFromSchemaSql(), []);
      return await runner(_store);
    }
    throw e;
  }
}

// Column order used for INSERT — kept as a constant so the placeholders
// list and the values list stay in sync. Must match the session table's
// schema in db.js (single-node) and framework-schema.js (cluster mode).
var SESSION_COLS = ["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"];

function _hashSid(sid) {
  return sha3Hash(SID_NAMESPACE + sid);
}

// Sealed-cookie format. `b.vault.seal` produces a `vault:`-prefixed
// envelope (ML-KEM-1024 + P-384 hybrid + XChaCha20-Poly1305). Pre-
// v0.8.61 the framework returned the plaintext sid to the caller; the
// sealed default since v0.8.61 keeps the wire token as ciphertext. The
// DB still keys on `sha3('bj-session:' || sid)` — sealing is a
// wire-format upgrade, not a storage change.
//
// Pre-v1.0 the framework ships no backwards-compat path: raw-format
// cookies from before v0.8.61 fail to unseal here and the affected
// caller force-logs-out (re-auths and gets a sealed cookie). The
// upgrade is operator-visible and documented in the release notes.
var SEALED_COOKIE_PREFIX = "vault:";

function _sealCookieToken(sid) {
  // vault.seal is idempotent on already-sealed input. Defensive null
  // pass-through matches vault's contract — feed it the raw sid only.
  return vault().seal(sid);
}

function _unsealCookieToken(token) {
  if (typeof token !== "string" || token.length === 0) return null;
  if (token.indexOf(SEALED_COOKIE_PREFIX) !== 0) {
    // Pre-v0.8.61 raw-sid format — refused under the sealed-cookie
    // default. Returning null surfaces as "session not found" at the
    // verify call site so the caller force-logs-out cleanly.
    return null;
  }
  try { return vault().unseal(token); }
  catch (_e) {
    // Tampered cookie / wrong keypair / vault rotation skew — treat as
    // not-found. The caller already handles `null` (re-auth flow).
    return null;
  }
}

// Build a sealed row object with all SESSION_COLS keys present (null
// where not set). The cryptoField.sealRow call seals userId/data and
// produces userIdHash from userId.
function _sealForInsert(row) {
  var sealed = cryptoField.sealRow(SESSION_TABLE, row);
  for (var i = 0; i < SESSION_COLS.length; i++) {
    if (!(SESSION_COLS[i] in sealed)) sealed[SESSION_COLS[i]] = null;
  }
  return sealed;
}

// ---- Public API ----

// Build a stable fingerprint from a request's client-derived signals.
// Operators opt in via session.create({ req, fingerprintFields }) and
// session.verify({ req, ... }); when the fingerprint drifts (different
// IP / user-agent / accept-language), the verify result carries
// fingerprintDrift: true and an audit event fires. Operators in strict
// mode pass requireFingerprintMatch:true to make the drift kill the
// session; default returns the session (so a phone roaming between
// wifi and LTE doesn't get logged out, but the operator AND ops sees
// the drift signal).
//
// The fingerprint is HMAC'd with the session sid so a stolen DB can't
// be cross-correlated with public IP-UA logs to attribute sessions to
// users — same defense the sidHash already provides for the token
// itself, extended to the fingerprint.
var DEFAULT_FINGERPRINT_FIELDS = ["clientIp", "userAgent", "acceptLanguage"];

// Subnet binding: roaming carriers (T-Mobile / Verizon / etc.) flip the
// public client IP every few requests as the device hops cells, so a strict
// full-IP fingerprint logs out healthy mobile users. The "clientIpPrefix"
// field hashes the /24 (IPv4) + /64 (IPv6) subnet bucket instead — drift
// across the bucket is meaningfully suspicious, drift within is not. The
// masking lives in requestHelpers.ipPrefix (the IP-utilities home, next to
// clientIp / trustedClientIp); operators with stricter needs pass a
// function-form fingerprint field and reuse requestHelpers.ipPrefix for a
// custom mask width.

// Resolve the per-call client-IP function for the clientIp / clientIpPrefix
// fingerprint fields. With { trustedProxies } (an array/string of CIDRs) or a
// custom { clientIpResolver }, the IP is peer-gated through
// requestHelpers.trustedClientIp so a deployment behind a trusted proxy binds
// the session to the real client and not the proxy address (which silently
// defeats the IP component of the fingerprint). With neither, it falls back to
// the bare-socket peer — the historical default, preserved so existing
// fingerprints don't change and log users out. The SAME option must be passed
// to create / verify / rotate (exactly like fingerprintFields) or the
// fingerprint won't match across the session lifecycle. An invalid CIDR throws
// at the call (config-time entry-point validation).
function _clientIpResolver(opts) {
  if (opts && (opts.trustedProxies != null || typeof opts.clientIpResolver === "function")) {
    return requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      clientIpResolver: opts.clientIpResolver,
    }).resolve;
  }
  return requestHelpers.clientIp;
}

function _buildFingerprintInputs(req, fields, resolveIp) {
  if (!req) return null;
  resolveIp = resolveIp || requestHelpers.clientIp;
  var headers = req.headers || {};
  var inputs = {};
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    if (f === "clientIp") {
      inputs.clientIp = resolveIp(req) || "";
    } else if (f === "clientIpPrefix") {
      // /24 v4 + /64 v6 — see requestHelpers.ipPrefix commentary.
      inputs.clientIpPrefix = requestHelpers.ipPrefix(resolveIp(req) || "");
    } else if (f === "userAgent") {
      inputs.userAgent = String(headers["user-agent"] || "");
    } else if (f === "acceptLanguage") {
      // Take only the primary tag (en-US,en;q=0.9 → en-US) so a
      // browser's secondary q-list reordering doesn't flap drift.
      var raw = String(headers["accept-language"] || "");
      var primary = raw.split(",")[0] || "";
      inputs.acceptLanguage = primary.split(";")[0].trim().toLowerCase();
    } else if (typeof f === "function") {
      try { inputs[f.name || ("custom" + i)] = String(f(req) || ""); }
      catch (_e) { inputs[f.name || ("custom" + i)] = ""; }
    }
  }
  return inputs;
}

function _hashFingerprint(sid, inputs) {
  if (!inputs) return null;
  // Deterministic stringify with sorted keys at every depth — refuses to
  // silently round-trip Date / Buffer / Map / Set / BigInt to "{}".
  var canonical = canonicalJson.stringify(inputs);
  return sha3Hash("bj-session-fingerprint:" + sid + ":" + canonical);
}

/**
 * @primitive b.session.create
 * @signature b.session.create(opts)
 * @since     0.1.0
 * @related   b.session.verify, b.session.rotate, b.session.destroy
 *
 * Mint a fresh session for a known userId and return the plaintext sid
 * the caller stores client-side (cookie / authorization header). The
 * sid is 32 random bytes (256-bit entropy floor); the DB stores
 * `sha3('bj-session:' || sid)` so DB exfiltration alone cannot
 * impersonate the session. `data` is vault-sealed JSON; `userId` is
 * sealed; a derived `userIdHash` indexes for fast `destroyAllForUser`.
 * Leader-only — followers raise NotLeaderError.
 *
 * Pass `{ req, fingerprintFields }` to bind the session to a stable
 * hash of client-IP / user-agent / accept-language; the binding is
 * checked on every `verify` call.
 *
 * @opts
 *   {
 *     userId:              string,                // required — opaque user id (sealed at rest)
 *     data?:               object,                // optional sealed JSON payload
 *     ttlMs?:              number,                // session lifetime; default 7d, max ~10y
 *     req?:                IncomingMessage,       // bind fingerprint to this request's signals
 *     fingerprintFields?:  Array<string|fn>,      // default ["clientIp","userAgent","acceptLanguage"]
 *   }
 *
 * @example
 *   var s = await b.session.create({
 *     userId: "user-42",
 *     data:   { roles: ["admin"] },
 *     ttlMs:  b.constants.TIME.hours(8),
 *   });
 *   res.setHeader("Set-Cookie", "sid=" + s.token + "; HttpOnly; Secure; SameSite=Strict");
 *   // → { token: "9f2c…", expiresAt: 1735689600000 }
 */
// Anonymous-session prefix. b.session.create({ anonymous: true })
// auto-mints userId = ANON_PREFIX + crypto.randomUUID() so operators
// running pre-login flows (cart, partial-funnel telemetry, public
// landing-page personalization) keep the framework's full sealed-
// cookie + sealed-userId + sidHash + idle/absolute timeout posture
// without rolling their own opaque-id pattern. destroyAllForUser
// refuses anon ids: they're per-session and aren't portable.
var ANON_PREFIX = "anon:";
function _isAnonymousUserId(id) {
  return typeof id === "string" && id.indexOf(ANON_PREFIX) === 0;
}

async function create(opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (opts.anonymous === true) {
    if (opts.userId !== undefined && opts.userId !== null) {
      throw _err("INVALID_ARG",
        "session.create: pass either anonymous: true OR userId, not both", true);
    }
    // crypto.randomUUID is the framework's existing entropy source
    // for opaque ids; anon sessions inherit the same 122-bit space.
    var nodeCryptoForUuid = require("node:crypto");                                                // allow:inline-require — only the anon path needs randomUUID
    opts = Object.assign({}, opts, { userId: ANON_PREFIX + nodeCryptoForUuid.randomUUID() });
  }
  if (!opts.userId) {
    throw _err("INVALID_ARG", "session.create requires { userId } (or { anonymous: true })", true);
  }
  var ttl = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULT_TTL_MS;
  _validateTtl(ttl, "session.create");

  var sid       = generateToken(SID_BYTES);      // hex-encoded; only place the plaintext sid lives
  var sidHash   = _hashSid(sid);
  var nowMs     = Date.now();
  var expiresAt = nowMs + ttl;

  // Fingerprint capture (opt-in via opts.req). Stored as a reserved
  // key inside the sealed `data` field so it lives alongside the
  // operator-supplied session data without needing a schema column.
  var dataObj = opts.data ? Object.assign({}, opts.data) : null;
  var fpFields = Array.isArray(opts.fingerprintFields) && opts.fingerprintFields.length > 0
    ? opts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
  var fpInputs = _buildFingerprintInputs(opts.req, fpFields, _clientIpResolver(opts));
  if (fpInputs) {
    if (!dataObj) dataObj = {};
    dataObj.__bj_fingerprint = _hashFingerprint(sid, fpInputs);
  }

  var sealed = _sealForInsert({
    sidHash:      sidHash,
    userId:       opts.userId,
    data:         dataObj ? JSON.stringify(dataObj) : null,
    createdAt:    nowMs,
    expiresAt:    expiresAt,
    lastActivity: nowMs,
  });
  var insertRow = {};
  for (var ci = 0; ci < SESSION_COLS.length; ci++) insertRow[SESSION_COLS[ci]] = sealed[SESSION_COLS[ci]];
  var built = sql.insert(_sessionSqlTable(), _sessionSqlOpts())
    .columns(SESSION_COLS)
    .values(insertRow)
    .toSql();
  await _currentStore().execute(built.sql, built.params);

  return { token: _sealCookieToken(sid), expiresAt: expiresAt };
}

/**
 * @primitive b.session.verify
 * @signature b.session.verify(token, opts?)
 * @since     0.1.0
 * @related   b.session.create, b.session.touch, b.session.rotate
 *
 * Look up a session by its plaintext sid, enforce TTL + idle +
 * absolute timeouts, optionally check fingerprint drift, and return
 * the unsealed payload. Returns `null` for unknown / expired / idle-
 * expired / absolute-expired sessions; runs anywhere (leader or
 * follower). On expiry, leader nodes best-effort delete the row;
 * followers skip cleanup.
 *
 * `idleTimeoutMs` defaults to 30 minutes, `absoluteTimeoutMs` to 12
 * hours; pass 0 to disable either floor. Pass `{ req }` to evaluate
 * the bound fingerprint — the result carries `fingerprintDrift: true`
 * on mismatch (audit event always fires). `requireFingerprintMatch:
 * true` or a `maxAnomalyScore` threshold (with a `scorer` callback)
 * makes drift refuse the session by returning `null`.
 *
 * @opts
 *   {
 *     idleTimeoutMs?:            number,          // default 30m; 0 disables
 *     absoluteTimeoutMs?:        number,          // default 12h; 0 disables
 *     req?:                      IncomingMessage, // for fingerprint check
 *     fingerprintFields?:        Array<string|fn>,
 *     requireFingerprintMatch?:  boolean,         // strict — drift kills the session
 *     maxAnomalyScore?:          number,          // 0..1; drift above kills
 *     scorer?:                   function,        // ({storedHash,currentInputs,currentHash,sessionAge}) -> 0..1
 *   }
 *
 * @example
 *   var info = await b.session.verify(req.cookies.sid, { req: req });
 *   if (!info) {
 *     res.statusCode = 401;
 *     res.end("login required");
 *     return;
 *   }
 *   var userId = info.userId;
 *   var roles  = (info.data && info.data.roles) || [];
 *   // → { userId: "user-42", data: { roles: ["admin"] }, createdAt: ..., expiresAt: ..., lastActivity: ..., fingerprintDrift: false, fingerprintAnomalyScore: null }
 */
// Evaluate the idle + absolute timeout floors against a session row.
// Returns { action, metadata } describing the breach, or null if the session
// is within both floors. Centralized so EVERY session-read path (verify,
// touch, ...) enforces the floors identically — a refresh must never
// resurrect a session that verify() would expire.
function _timeoutFloorBreach(row, nowMs, opts) {
  opts = opts || {};
  var idleMs = opts.idleTimeoutMs !== undefined ? opts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
  var absMs = opts.absoluteTimeoutMs !== undefined ? opts.absoluteTimeoutMs : DEFAULT_ABSOLUTE_TIMEOUT_MS;
  if (idleMs > 0) {
    var lastActivity = Number(row.lastActivity);
    if ((nowMs - lastActivity) > idleMs) {
      return { action: "auth.session.expired_idle", metadata: { idleMs: nowMs - lastActivity, threshold: idleMs } };
    }
  }
  if (absMs > 0) {
    var createdAt = Number(row.createdAt);
    if ((nowMs - createdAt) > absMs) {
      return { action: "auth.session.expired_absolute", metadata: { ageMs: nowMs - createdAt, threshold: absMs } };
    }
  }
  return null;
}

async function verify(token, verifyOpts) {
  if (typeof token !== "string" || token.length === 0) return null;
  verifyOpts = verifyOpts || {};
  // Sealed-cookie default — unseal the wire token to recover the sid.
  // Pre-v0.8.61 raw cookies / tampered envelopes return null and the
  // caller re-auths. The plaintext sid never leaves this function.
  var sid = _unsealCookieToken(token);
  if (sid === null) return null;
  var sidHash = _hashSid(sid);

  var selBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["sidHash", "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"])
    .where("sidHash", sidHash)
    .toSql();
  var row = await _currentStore().executeOne(selBuilt.sql, selBuilt.params);
  if (!row) return null;
  var nowMs = Date.now();
  if (Number(row.expiresAt) < nowMs) {
    // Expired (operator-set ttl) — clean up and return null. Cleanup
    // is leader-only; verify is anywhere, so a follower observing an
    // expired row skips the cleanup (next leader-side call purges it).
    if (cluster.isLeader()) {
      try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    }
    return null;
  }

  // Idle + absolute timeout enforcement (OWASP ASVS 5.0 §3.3 / NIST
  // SP 800-63B-4). These shorten the effective lifetime even when the
  // operator picked a long ttlMs. Defaults: idle 30m, absolute 12h.
  // Operator opt-out by passing 0 (disables that timeout).
  var floorBreach = _timeoutFloorBreach(row, nowMs, verifyOpts);
  if (floorBreach) {
    try {
      audit.safeEmit({ action: floorBreach.action, outcome: "success", metadata: floorBreach.metadata });
    } catch (_ignored) { /* audit best-effort */ }
    if (cluster.isLeader()) {
      try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    }
    return null;
  }
  // Unseal sealed columns (userId, data) using the cryptoField pipeline
  // so we return cleartext to the caller — same shape as the previous
  // db().from(...).first() path delivered.
  var unsealed = cryptoField.unsealRow(SESSION_TABLE, row);
  var data = null;
  var storedFingerprint = null;
  // The sealed `data` cell carries the device-fingerprint binding. A cell that
  // EXISTS on the row but does not decrypt (key-rotation skew, DB corruption, or
  // a tamper of the independently-AEAD-sealed column) means the binding is
  // UNREADABLE — distinct from a session that legitimately carries no binding.
  // Under a strict binding policy that must FAIL CLOSED below, not be skipped.
  var bindingUnreadable = (row.data != null && row.data !== "" && unsealed.data == null);
  if (unsealed.data) {
    try {
      data = safeJson.parse(unsealed.data);
      if (data && typeof data === "object" && typeof data.__bj_fingerprint === "string") {
        storedFingerprint = data.__bj_fingerprint;
        // Strip the reserved key from the operator-visible data so
        // routes don't accidentally render it / log it / pass it on.
        delete data.__bj_fingerprint;
        if (Object.keys(data).length === 0) data = null;
      }
    }
    catch (e) {
      // Decrypt-then-parse failure is rare but operationally important —
      // it usually signals key-rotation skew, DB corruption, or
      // tampering. Emit an audit event so ops can spot it before the
      // operator notices empty-`data` flows. data stays null so the
      // session remains usable for non-data flows.
      data = null;
      bindingUnreadable = true;   // decrypted but unparseable — binding unreadable
      try {
        audit.safeEmit({
          action:   "auth.session.data_unparseable",
          outcome:  "failure",
          reason:   (e && e.message) || String(e),
          metadata: { hasUserId: !!unsealed.userId },
        });
      } catch (_ignored) { /* audit best-effort */ }
    }
  }

  // Fingerprint check — opt-in via verifyOpts.req. When the stored
  // fingerprint differs from the current request's fingerprint, audit
  // the drift and (in strict mode) refuse the session. Default mode
  // returns the session with `fingerprintDrift: true` so the operator
  // can decide (some drift — phone roaming wifi/LTE — is benign; a
  // login-from-Tokyo-then-immediately-from-Brazil pattern is not).
  var fingerprintDrift = false;
  var fingerprintAnomalyScore = null;
  // A strict binding policy (requireFingerprintMatch / maxAnomalyScore) cannot be
  // satisfied when the binding is UNREADABLE — we can't prove it matches, so fail
  // CLOSED rather than silently skipping the gate (the pre-fix fail-open).
  if (bindingUnreadable && verifyOpts.req &&
      (verifyOpts.requireFingerprintMatch === true ||
       typeof verifyOpts.maxAnomalyScore === "number")) {
    try {
      audit.safeEmit({
        action:   "auth.session.binding_unreadable",
        outcome:  "failure",
        metadata: { hasUserId: !!unsealed.userId },
      });
    } catch (_ig) { /* audit best-effort */ }
    return null;
  }
  if (storedFingerprint && verifyOpts.req) {
    var fpFields = Array.isArray(verifyOpts.fingerprintFields) && verifyOpts.fingerprintFields.length > 0
      ? verifyOpts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
    var currentInputs = _buildFingerprintInputs(verifyOpts.req, fpFields, _clientIpResolver(verifyOpts));
    var currentHash = _hashFingerprint(sid, currentInputs);
    if (currentHash !== storedFingerprint) {
      fingerprintDrift = true;
      // Operator-supplied scorer: receives { storedHash, currentInputs,
      // currentHash, sessionAge: ms-since-create }. Returns a number
      // in [0, 1] — 0 = benign drift (phone roaming wifi), 1 =
      // definitely-malicious. Errors are swallowed; scorer-throw
      // doesn't break verify.
      if (typeof verifyOpts.scorer === "function") {
        try {
          var rawScore = verifyOpts.scorer({
            storedHash:    storedFingerprint,
            currentInputs: currentInputs,
            currentHash:   currentHash,
            sessionAge:    Date.now() - Number(unsealed.createdAt),
          });
          if (typeof rawScore === "number" && isFinite(rawScore)) {
            fingerprintAnomalyScore = Math.max(0, Math.min(1, rawScore));
          }
        } catch (_e) { /* scorer best-effort */ }
      }
      try {
        audit.safeEmit({
          action:   "auth.session.fingerprint_drift",
          outcome:  "success",
          metadata: { hasUserId: !!unsealed.userId,
            anomalyScore: fingerprintAnomalyScore },
        });
      } catch (_ignored) { /* audit best-effort */ }
      // Strict modes:
      //   requireFingerprintMatch: true       — any drift kills the session
      //   maxAnomalyScore: <0..1>             — drift above threshold kills
      if (verifyOpts.requireFingerprintMatch === true) {
        return null;
      }
      if (typeof verifyOpts.maxAnomalyScore === "number" &&
          fingerprintAnomalyScore !== null &&
          fingerprintAnomalyScore > verifyOpts.maxAnomalyScore) {
        return null;
      }
    }
  }

  return {
    userId:                   unsealed.userId,
    data:                     data,
    createdAt:                Number(unsealed.createdAt),
    expiresAt:                Number(unsealed.expiresAt),
    lastActivity:             Number(unsealed.lastActivity),
    fingerprintDrift:         fingerprintDrift,
    fingerprintAnomalyScore:  fingerprintAnomalyScore,
  };
}

/**
 * @primitive b.session.destroy
 * @signature b.session.destroy(token)
 * @since     0.1.0
 * @related   b.session.destroyAllForUser, b.session.create
 *
 * Revoke a single session by sid. Returns `true` when a row was
 * deleted, `false` when the sid is unknown / already gone / empty.
 * Standard logout flow: clear the client's cookie AND call
 * `destroy(sid)` so the row vanishes from the DB and verify(sid)
 * starts returning null cluster-wide. Leader-only.
 *
 * @example
 *   await b.session.destroy(req.cookies.sid);
 *   res.setHeader("Set-Cookie", "sid=; HttpOnly; Max-Age=0");
 *   res.end("logged out");
 *   // → true
 */
async function destroy(token) {
  cluster.requireLeader();
  if (typeof token !== "string" || token.length === 0) return false;
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  return await _deleteBySidHash(_hashSid(sid));
}

/**
 * @primitive b.session.logout
 * @signature b.session.logout(res, token, opts?)
 * @since     0.15.9
 * @status    stable
 * @related   b.session.destroy, b.middleware.clearSiteData
 *
 * Secure logout in one call: destroy the server-side session AND tell the
 * browser to wipe its client-side state. It emits an RFC 9527 Clear-Site-Data
 * response header (cookies + storage + cache + executionContexts by default)
 * and expires the session cookie, then destroys the session row. `destroy()`
 * alone is a store operation with no `res`, so it cannot wipe the browser's
 * cached pages / storage / any stale tab still holding the now-revoked cookie;
 * this composes the secure-default logout the middleware otherwise had to be
 * mounted by hand. Returns whether a session was destroyed. Leader-only.
 *
 * @opts
 *   cookieName: string,    // default: "sid" — the session cookie to expire
 *   types:      string[],  // default: the RFC 9527 Clear-Site-Data directive set
 *
 * @example
 *   app.post("/logout", async function (req, res) {
 *     await b.session.logout(res, req.cookies.sid);
 *     res.end("logged out");
 *   });
 *   // → emits Clear-Site-Data + expires the sid cookie + destroys the session
 */
async function logout(res, token, opts) {
  if (!res || typeof res.setHeader !== "function") {
    throw new SessionError("session/bad-res",
      "b.session.logout: res must be an HTTP response with setHeader()");
  }
  opts = opts || {};
  var cookieName = opts.cookieName === undefined ? "sid" : opts.cookieName;
  if (typeof cookieName !== "string" || cookieName.length === 0) {
    throw new SessionError("session/bad-cookie-name",
      "b.session.logout: opts.cookieName must be a non-empty string");
  }
  var csd = clearSiteData();
  var types = opts.types === undefined ? csd.DEFAULT_TYPES : opts.types;
  // Build (and validate) the RFC 9527 header BEFORE any side effect — an
  // unknown directive throws here, queuing nothing.
  var clearSiteDataValue = csd.headerValue(types, "b.session.logout");

  // Revoke the server-side session FIRST. If destroy() throws (a follower
  // failing cluster.requireLeader(), or a store/DB error), no client-wipe
  // headers have been queued — an error response can't then expire the
  // browser cookie + Clear-Site-Data while the session row is still live,
  // which would leave a copied token usable server-side.
  var destroyed = await destroy(token);

  // Now wipe the client-side state: RFC 9527 Clear-Site-Data (cookies /
  // storage / cache) + expire the session cookie (belt-and-suspenders with the
  // "cookies" directive, and effective even if the client ignores the header).
  res.setHeader("Clear-Site-Data", clearSiteDataValue);
  res.setHeader("Set-Cookie",
    cookieName + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
  return destroyed;
}

async function _deleteBySidHash(sidHash) {
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .where("sidHash", sidHash)
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
  return (result.rowCount || 0) > 0;
}

/**
 * @primitive b.session.destroyAllForUser
 * @signature b.session.destroyAllForUser(userId)
 * @since     0.1.0
 * @related   b.session.destroy, b.session.rotate
 *
 * Revoke every active session for a userId at once. Returns the count
 * of rows deleted. Use after password change, role revocation,
 * compromised-account reports, or "log me out everywhere" UI flows.
 * Lookup goes through the derived `userIdHash` — no row needs
 * unsealing to find matches. Leader-only.
 *
 * @example
 *   var revoked = await b.session.destroyAllForUser("user-42");
 *   b.audit.emit({ action: "auth.session.revoke_all", outcome: "success",
 *     metadata: { userId: "user-42", count: revoked } });
 *   // → 3
 */
async function destroyAllForUser(userId) {
  cluster.requireLeader();
  if (!userId) throw _err("INVALID_ARG", "session.destroyAllForUser requires a userId", true);
  if (_isAnonymousUserId(userId)) {
    // Anon ids are minted per-session and aren't reused — destroying
    // "all" anon sessions for one anon id is the same as destroying
    // that single session. Refuse loudly so the operator doesn't
    // think they're sweeping across an anon population.
    throw _err("INVALID_ARG",
      "session.destroyAllForUser: anonymous-prefix ids (\"anon:...\") are per-session — " +
      "use destroy(token) for that session, OR purgeExpired() for housekeeping",
      true);
  }
  // userId is sealed; look up via derived userIdHash.
  var lookup = cryptoField.lookupHash(SESSION_TABLE, "userId", userId);
  if (!lookup) {
    // The session table's userIdHash derived-hash schema is registered during
    // b.db.init(). A pluggable-store consumer (b.session.useStore) who never
    // called b.db.init() lands here first — surface that, not just an opaque
    // "framework misconfigured", since destroyAllForUser still needs b.db for
    // the userIdHash index + the stateless valid-from boundary.
    throw _err("MISCONFIGURED",
      "session.destroyAllForUser: the session table's userIdHash derived-hash schema is " +
      "not registered. It is registered during b.db.init() — call b.db.init() at boot even " +
      "when session data lives in a pluggable store (b.session.useStore). If b.db is already " +
      "initialized, the session table schema is misconfigured.",
      true);
  }
  // Dual-read across the keyed-MAC flip: a pre-v0.15.0 session row carries
  // the legacy salted-sha3 userIdHash, so destroy must match both digests
  // or it leaves un-migrated sessions for the user un-revoked.
  var userHashes = [lookup.value];
  if (lookup.legacyValue != null && lookup.legacyValue !== lookup.value) {
    userHashes.push(lookup.legacyValue);
  }
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .whereIn("userIdHash", userHashes)
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
  // Also raise the stateless valid-from boundary so a "logout everywhere"
  // revokes the operator's stateless tokens (sealed cookies / JWTs checked via
  // b.session.check) too, not only the store-backed rows just deleted. bump()
  // writes to the framework db when one is initialized, otherwise to the
  // configured store (b.session.useStore) — so a store-backed-only consumer who
  // never ran b.db.init() still raises the boundary here instead of 500ing on
  // db/not-initialized (#340). The only state in which bump still surfaces
  // db/not-initialized is the default store (no useStore) with an uninitialized
  // framework db — but the store DELETE above (also via clusterStorage) would
  // have already thrown, so this rewrap is defensive belt-and-suspenders.
  try {
    await bump(userId);
  } catch (e) {
    if (e && e.code === "db/not-initialized") {
      throw _err("MISCONFIGURED",
        "session.destroyAllForUser raises the stateless valid-from boundary (so a " +
        "logout-everywhere also revokes sealed-cookie / JWT sessions). No storage is " +
        "available: call b.db.init() at boot, OR configure a session store via " +
        "b.session.useStore. The store-backed rows were already deleted.", true);
    }
    throw e;
  }
  return result.rowCount || 0;
}

/**
 * @primitive b.session.touch
 * @signature b.session.touch(token, opts)
 * @since     0.1.0
 * @related   b.session.verify, b.session.rotate
 *
 * Refresh `lastActivity` (resets the idle-timeout countdown) and
 * optionally extend `expiresAt`. Returns `true` when a non-expired
 * row was updated, `false` when the sid is unknown or the row is
 * already past its TTL. Pass `extendBy` to push `expiresAt` forward
 * relative to NOW (not the existing expiry — soaked sessions with
 * continuous traffic don't accumulate unbounded expiry); the
 * framework's MAX_TTL_MS bound applies. Leader-only.
 *
 * @opts
 *   {
 *     extendBy?: number,   // ms to set new expiresAt = now + extendBy
 *   }
 *
 * @example
 *   // Bump idle clock on every request:
 *   await b.session.touch(req.cookies.sid);
 *
 *   // Sliding-window: extend by another 8 hours when activity continues.
 *   await b.session.touch(req.cookies.sid, { extendBy: b.constants.TIME.hours(8) });
 *   // → true
 */
async function touch(token, opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  var sidHash = _hashSid(sid);
  var nowMs = Date.now();
  // A session past its idle / absolute timeout floor must not be resurrected
  // by a refresh — enforce the floors (as verify does) before extending.
  // Without this, touch() would reset lastActivity on a session verify()
  // would have expired, defeating the floor.
  var floorSel = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["createdAt", "lastActivity"])
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var floorRow = await _currentStore().executeOne(floorSel.sql, floorSel.params);
  if (!floorRow) return false;
  if (_timeoutFloorBreach(floorRow, nowMs, opts)) {
    try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
    return false;
  }
  // Two SQL paths so the SET list stays static (no dynamic column
  // assembly) and matches the call shape clusterStorage expects.
  // extendBy resets expiresAt relative to NOW, not relative to the
  // current expiresAt — a soaked session with continuous traffic
  // shouldn't accumulate unbounded expiry. The same MAX_TTL_MS
  // ceiling create() and rotate() apply gates extendBy too — repeated
  // touch() calls cannot push expiresAt past the framework's bound.
  if (opts.extendBy !== undefined && opts.extendBy !== null) {
    _validateTtl(opts.extendBy, "session.touch");
    var newExpires = nowMs + opts.extendBy;
    var built = sql.update(_sessionSqlTable(), _sessionSqlOpts())
      .set({ lastActivity: nowMs, expiresAt: newExpires })
      .where("sidHash", sidHash)
      .where("expiresAt", ">=", nowMs)
      .toSql();
    var result = await _currentStore().execute(built.sql, built.params);
    return (result.rowCount || 0) > 0;
  }
  var built2 = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set({ lastActivity: nowMs })
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result2 = await _currentStore().execute(built2.sql, built2.params);
  return (result2.rowCount || 0) > 0;
}

/**
 * @primitive b.session.rotate
 * @signature b.session.rotate(oldToken, opts)
 * @since     0.1.0
 * @related   b.session.create, b.session.verify, b.session.destroy
 *
 * Session-fixation defense: generate a fresh sid for the same userId +
 * data, atomically replacing the old sid in the row. Call after every
 * auth state change (login from anonymous, multifactor verified, role
 * escalation) so any sid an attacker planted pre-login becomes invalid.
 * Returns `{ token, expiresAt }` on success, `null` when the old token
 * is unknown / expired (operator distinguishes by checking for null).
 * Leader-only.
 *
 * Atomicity: a single WHERE-guarded UPDATE swaps `sidHash`. The old
 * and new tokens never coexist — the moment the UPDATE commits, only
 * the new token verifies. Audit event `auth.session.rotate` fires
 * best-effort with `metadata.reason`.
 *
 * Device binding: when the session was created with `{ req, fingerprintFields }`
 * the bound fingerprint is keyed to the sid, so rotation re-keys it to the new
 * sid from the live request. Pass the same `{ req, fingerprintFields }` to
 * `rotate` — a fingerprint-bound session rotated without `req` throws, because
 * the binding cannot follow the sid otherwise (it would silently break or make
 * the next `verify` falsely report drift).
 *
 * @opts
 *   {
 *     data?:              object,     // replacement session data (re-sealed)
 *     ttlMs?:             number,     // new TTL; if absent, existing expiresAt preserved
 *     reason?:            string,     // audit metadata ("login", "mfa", "role-change")
 *     req?:               IncomingMessage, // re-key the device fingerprint to the new sid
 *     fingerprintFields?: Array<string|fn>, // default ["clientIp","userAgent","acceptLanguage"]
 *   }
 *
 * @example
 *   var rotated = await b.session.rotate(req.cookies.sid, {
 *     ttlMs:  b.constants.TIME.hours(8),
 *     reason: "mfa",
 *   });
 *   if (rotated) {
 *     res.setHeader("Set-Cookie", "sid=" + rotated.token + "; HttpOnly; Secure; SameSite=Strict");
 *   }
 *   // → { token: "7a1e…", expiresAt: 1735689600000 }
 */
async function rotate(oldToken, opts) {
  cluster.requireLeader();
  if (typeof oldToken !== "string" || oldToken.length === 0) return null;
  opts = opts || {};
  var oldSid = _unsealCookieToken(oldToken);
  if (oldSid === null) return null;

  var newSid       = generateToken(SID_BYTES);
  var newSidHash   = _hashSid(newSid);
  var oldSidHash   = _hashSid(oldSid);
  var nowMs        = Date.now();
  var newExpires = null;
  if (opts.ttlMs !== undefined) {
    _validateTtl(opts.ttlMs, "session.rotate");
    newExpires = nowMs + opts.ttlMs;
  }

  var setCols = { sidHash: newSidHash, lastActivity: nowMs };

  // Re-key the device binding to the NEW sid. __bj_fingerprint is sid-keyed
  // (_hashFingerprint(sid, inputs), so a stolen DB can't replay it); a rotated
  // session that kept the old-sid hash would make verify(newToken, sameReq)
  // recompute against the new sid and mismatch — a false fingerprintDrift
  // (strict operators destroy the session on every rotation) or a silently
  // broken binding. Read the live row to learn whether the session was bound
  // and to carry its payload forward when opts.data is not supplied.
  var fpFields = Array.isArray(opts.fingerprintFields) && opts.fingerprintFields.length > 0
    ? opts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
  var existingData = null;
  var rotSelBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["data"])
    .where("sidHash", oldSidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var existingRow = await _currentStore().executeOne(rotSelBuilt.sql, rotSelBuilt.params);
  if (!existingRow) return null;   // unknown / expired old session
  try {
    var unsealedExisting = cryptoField.unsealRow(SESSION_TABLE, existingRow);
    if (unsealedExisting.data) existingData = safeJson.parse(unsealedExisting.data);
  } catch (_e) { existingData = null; }
  var wasBound = existingData && typeof existingData === "object" &&
                 typeof existingData.__bj_fingerprint === "string";

  if (opts.data !== undefined || wasBound) {
    // opts.data REPLACES the payload (documented rotate semantics); otherwise
    // carry the existing payload forward. The reserved __bj_fingerprint is
    // never copied verbatim (it is old-sid-keyed) — it is recomputed below.
    var newDataObj;
    if (opts.data !== undefined) {
      newDataObj = (opts.data && typeof opts.data === "object") ? Object.assign({}, opts.data) : null;
    } else {
      newDataObj = (existingData && typeof existingData === "object") ? Object.assign({}, existingData) : null;
    }
    if (newDataObj) delete newDataObj.__bj_fingerprint;

    if (wasBound) {
      if (!opts.req) {
        throw _err("ROTATE_FINGERPRINT_REQ_REQUIRED",
          "session.rotate: this session is fingerprint-bound; pass { req, fingerprintFields } " +
          "so the device binding can be re-keyed to the new session id", true);
      }
      if (!newDataObj) newDataObj = {};
      newDataObj.__bj_fingerprint = _hashFingerprint(newSid, _buildFingerprintInputs(opts.req, fpFields, _clientIpResolver(opts)));
    }

    var dataJson = newDataObj ? JSON.stringify(newDataObj) : null;
    var sealedRow = cryptoField.sealRow(SESSION_TABLE, { data: dataJson });
    setCols.data = sealedRow.data;
  }
  if (newExpires !== null) {
    setCols.expiresAt = newExpires;
  }

  var updBuilt = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set(setCols)
    .where("sidHash", oldSidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result = await _currentStore().execute(updBuilt.sql, updBuilt.params);
  if ((result.rowCount || 0) === 0) return null;

  // Read the row's effective expiresAt to return — single source of truth.
  var rowBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["expiresAt"])
    .where("sidHash", newSidHash)
    .toSql();
  var row = await _currentStore().executeOne(rowBuilt.sql, rowBuilt.params);
  var expiresAt = row ? Number(row.expiresAt) : null;

  // Audit emit — best-effort. The framework's audit chain logs the
  // privilege transition so post-incident review can trace which
  // session id covered which privilege state.
  try {
    audit.emit({
      action:  "auth.session.rotate",
      outcome: "success",
      metadata: { reason: opts.reason || "explicit" },
    });
  } catch (_e) { /* audit emit best-effort — never block rotate() */ }

  return { token: _sealCookieToken(newSid), expiresAt: expiresAt };
}

/**
 * @primitive b.session.updateData
 * @signature b.session.updateData(token, data, opts?)
 * @since     0.8.66
 * @related   b.session.verify, b.session.rotate
 *
 * Update the sealed `data` payload on a session WITHOUT rotating the
 * sid. Use cases: cart-state writes, user-preference flips, step-up-
 * auth completion flags, fingerprint-anomaly score updates. Anything
 * that doesn't change the security boundary (login transition, role
 * escalation, multifactor verified) — those still go through
 * `b.session.rotate({ data })` so the sid moves and any pre-login
 * tokens an attacker may have planted become invalid.
 *
 * Default semantics:
 *   - `data` REPLACES the existing payload (full overwrite). The
 *     reserved `__bj_fingerprint` key is preserved automatically so
 *     fingerprint-binding survives the update.
 *   - `lastActivity` is bumped (idle-timeout reset) unless
 *     `opts.touchLastActivity: false`.
 *   - The session must be live (not expired) for the write to land;
 *     returns `false` for unknown / expired tokens.
 *
 * Pass `opts.merge: true` to deep-merge top-level keys into the
 * existing payload instead of replacing — useful for incremental
 * writes where the operator doesn't want to round-trip read+merge
 * themselves. Inner objects merge ONE LEVEL DEEP; arrays REPLACE.
 *
 * Leader-only.
 *
 * @opts
 *   {
 *     merge?:              boolean,   // default false (full replace)
 *     touchLastActivity?:  boolean,   // default true
 *   }
 *
 * @example
 *   // Replace the data payload entirely.
 *   await b.session.updateData(req.cookies.sid, { roles: ["admin"], theme: "dark" });
 *
 *   // Merge a single field without disturbing the rest of the payload.
 *   await b.session.updateData(req.cookies.sid,
 *     { stepUpAt: Date.now() }, { merge: true });
 *   // → true
 */
async function updateData(token, data, opts) {
  cluster.requireLeader();
  opts = opts || {};
  if (typeof token !== "string" || token.length === 0) return false;
  if (data !== null && (typeof data !== "object" || Array.isArray(data))) {
    throw _err("INVALID_ARG",
      "session.updateData: data must be a plain object or null", true);
  }
  var sid = _unsealCookieToken(token);
  if (sid === null) return false;
  var sidHash = _hashSid(sid);
  var nowMs = Date.now();

  // Read the live row so we can preserve __bj_fingerprint and (in
  // merge mode) carry forward existing keys. Single SELECT + UPDATE
  // — racing concurrent updateData calls fall through to last-write-
  // wins on the same sid, which is the right shape for cart-style
  // writes; operators needing strict serialization wrap with
  // b.resourceAccessLock.
  var selBuilt = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .columns(["userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity"])
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var row = await _currentStore().executeOne(selBuilt.sql, selBuilt.params);
  if (!row) return false;

  // Recover the existing data + reserved fingerprint key (vault-
  // sealed at rest). Operators that want a fresh fingerprint also
  // call b.session.rotate; updateData preserves the binding.
  var unsealed = cryptoField.unsealRow(SESSION_TABLE, row);
  var existing = null;
  var storedFingerprint = null;
  if (unsealed.data) {
    try {
      existing = safeJson.parse(unsealed.data);
      if (existing && typeof existing === "object" &&
          typeof existing.__bj_fingerprint === "string") {
        storedFingerprint = existing.__bj_fingerprint;
      }
    } catch (_e) {
      // Decrypt-then-parse failure mirrors verify() — drop existing
      // and proceed with the new payload only. Operator gets the
      // same auth.session.data_unparseable signal next verify().
      existing = null;
      storedFingerprint = null;
    }
  }

  // Build the next payload. merge:true does a one-level deep merge
  // into the existing object (arrays at the top level REPLACE);
  // default replaces wholesale.
  var next;
  if (opts.merge === true && existing && typeof existing === "object") {
    next = Object.assign({}, existing);
    if (data && typeof data === "object") {
      Object.keys(data).forEach(function (k) {
        if (k === "__bj_fingerprint") return;       // reserved — only fingerprint binding writes this
        next[k] = data[k];
      });
    }
  } else {
    next = (data && typeof data === "object") ? Object.assign({}, data) : null;
    if (next) delete next.__bj_fingerprint;          // reserved — operator can't overwrite the binding
  }
  if (storedFingerprint && next) next.__bj_fingerprint = storedFingerprint;

  // Re-seal the data column. cryptoField.sealRow handles the AAD
  // binding + sealedFields registration automatically.
  var sealedRow = cryptoField.sealRow(SESSION_TABLE, {
    data: next ? JSON.stringify(next) : null,
  });

  var setCols = { data: sealedRow.data };
  if (opts.touchLastActivity !== false) {
    setCols.lastActivity = nowMs;
  }
  var updBuilt = sql.update(_sessionSqlTable(), _sessionSqlOpts())
    .set(setCols)
    .where("sidHash", sidHash)
    .where("expiresAt", ">=", nowMs)
    .toSql();
  var result = await _currentStore().execute(updBuilt.sql, updBuilt.params);
  return (result.rowCount || 0) > 0;
}

/**
 * @primitive b.session.purgeExpired
 * @signature b.session.purgeExpired()
 * @since     0.1.0
 * @related   b.session.count, b.session.destroy
 *
 * Bulk-delete every row whose `expiresAt` is in the past. Returns the
 * count of rows removed. The framework purges opportunistically on
 * `verify` (leader-side), but a periodic sweep keeps the table from
 * accumulating dead rows when verify traffic is sparse. Safe to schedule
 * on a recurring timer (the framework's scheduler primitive is the
 * intended caller). Leader-only.
 *
 * @example
 *   // Hourly purge from a scheduler:
 *   b.scheduler.every(b.constants.TIME.hours(1), async function () {
 *     var dropped = await b.session.purgeExpired();
 *     b.audit.emit({
 *       action: "auth.session.purge_expired", outcome: "success",
 *       metadata: { dropped: dropped },
 *     });
 *   });
 *   // → 17
 */
async function purgeExpired() {
  cluster.requireLeader();
  var built = sql.delete(_sessionSqlTable(), _sessionSqlOpts())
    .where("expiresAt", "<", Date.now())
    .toSql();
  var result = await _currentStore().execute(built.sql, built.params);
  return result.rowCount || 0;
}

/**
 * @primitive b.session.count
 * @signature b.session.count()
 * @since     0.1.0
 * @related   b.session.purgeExpired, b.session.destroyAllForUser
 *
 * Return the number of currently-live sessions (rows whose `expiresAt`
 * is in the future). Useful for ops dashboards, capacity tracking, and
 * "active users" metrics. Runs anywhere — leader or follower — because
 * it only reads. Note that idle-timeout-eligible rows are still counted
 * until a `verify` or `purgeExpired` removes them; the value is an
 * upper bound on truly-active sessions.
 *
 * @example
 *   var live = await b.session.count();
 *   b.observability.event({ name: "session.live", value: live });
 *   // → 482
 */
async function count() {
  var built = sql.select(_sessionSqlTable(), _sessionSqlOpts())
    .count("*", "c")
    .where("expiresAt", ">=", Date.now())
    .toSql();
  var row = await _currentStore().executeOne(built.sql, built.params);
  // COUNT(*) aliased to `c` is not a framework-schema column, so
  // clusterStorage.coerceRows does not touch it; node-postgres / mysql2
  // hand a BIGINT count back as a decimal STRING. Number() at the read
  // boundary keeps single-node sqlite (native number) and the cluster
  // backends returning the same JS number.
  return row ? Number(row.c) : 0;
}

function _resetForTest() { _store = null; }

/**
 * @primitive b.session.useStore
 * @signature b.session.useStore(store)
 * @since     0.8.61
 * @status    stable
 * @related   b.session.stores.localDbThin
 *
 * Replace the default `_blamejs_sessions` storage backend (the
 * framework's main DB / external DB via cluster-storage) with an
 * operator-supplied store. The store must expose
 * `execute(sql, params)` and `executeOne(sql, params)` returning the
 * same `{ rows, rowCount }` / `row | null` shape `b.clusterStorage`
 * returns. Pass `null` to revert to the default.
 *
 * Typical use is to point session writes at an isolated SQLite file
 * (often tmpfs) so session churn doesn't fight the main DB's encrypted-
 * at-rest re-flush cycle. The first-party adapter is
 * `b.session.stores.localDbThin({ file })`.
 *
 * Call this once at boot, BEFORE the first `session.create` /
 * `session.verify`. Switching stores on a running app strands every
 * existing session in the old store.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   await b.vault.init({ dataDir: "/var/lib/blamejs", mode: "plaintext" });
 *   await b.db.init({ dataDir: "/var/lib/blamejs" });
 *   var sessionStore = b.session.stores.localDbThin({ file: "/dev/shm/sessions.db" });
 *   b.session.useStore(sessionStore);
 *   // Every b.session.* call now routes through the tmpfs file.
 */
function useStore(store) {
  if (store === null || store === undefined) {
    _store = null;
    return;
  }
  validateOpts.requireMethods(store, ["execute", "executeOne"],
    "session.useStore: store", SessionError, "INVALID_ARG", true);
  _store = store;
}

/**
 * @primitive b.session.isAnonymous
 * @signature b.session.isAnonymous(userId)
 * @since     0.8.62
 * @status    stable
 * @related   b.session.create
 *
 * Returns `true` if the supplied userId was minted by
 * `b.session.create({ anonymous: true })` (i.e., starts with the
 * `anon:` prefix). Operators use this to gate post-auth behavior
 * (e.g., refuse a payment confirmation when the session is still
 * anonymous, or render the "log in to continue" banner).
 *
 * @example
 *   var info = await b.session.verify(req.cookies.sid);
 *   if (info && b.session.isAnonymous(info.userId)) {
 *     res.statusCode = 401; res.end("login required"); return;
 *   }
 */
function isAnonymous(userId) {
  return _isAnonymousUserId(userId);
}

/**
 * @primitive b.session.bump
 * @signature b.session.bump(subjectId, opts?)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.check, b.session.validFrom, b.session.destroyAllForUser
 *
 * Revoke every STATELESS self-validating token (sealed cookie carrying no DB
 * row, JWT) for a subject by raising a durable per-subject valid-from boundary
 * to now. Any token whose issued-at (`iat`) predates the boundary fails
 * `b.session.check`. Unlike `destroyAllForUser` — which deletes server-side
 * session rows — this revokes tokens the framework never stored a row for:
 * log-out-everywhere, a right-to-erasure cutoff, a forced re-auth after a
 * password / key change. `destroyAllForUser` calls this for you, so a single
 * "logout everywhere" covers both store-backed and stateless tokens.
 *
 * The boundary is MONOTONIC: it only ever moves forward. A bump to an
 * `epochMs` at or below the stored value is a no-op — a replayed or
 * clock-skewed lower value can never widen a revoked window back open. Returns
 * the boundary in effect after the call. Leader-only. The subject id is stored
 * hashed; the plaintext id never lands in the table.
 *
 * @opts
 *   epochMs:  number,   // boundary to set; default Date.now(). Tokens with iat < this are revoked.
 *
 * @example
 *   // Force re-auth everywhere for a subject after a password change:
 *   var boundary = await b.session.bump("user-42");
 *   // Cut off at a specific instant (right-to-erasure effective time):
 *   await b.session.bump("user-42", { epochMs: erasureEffectiveMs });
 */
async function bump(subjectId, opts) {
  cluster.requireLeader();
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw _err("INVALID_ARG", "session.bump requires a non-empty subjectId", true);
  }
  opts = opts || {};
  var epochMs = opts.epochMs === undefined ? Date.now() : opts.epochMs;
  if (typeof epochMs !== "number" || !isFinite(epochMs) || epochMs < 0) {
    throw _err("INVALID_ARG",
      "session.bump: epochMs must be a non-negative finite number, got " + JSON.stringify(epochMs), true);
  }
  var subjectHash = _hashSubjectId(subjectId);
  var t = _validFromSqlTable();
  var dialect = clusterStorage.dialect();
  var refs = _validFromConflictRefs(dialect, t);

  // Monotonic-max conflict action: keep the LATER of the proposed and the
  // stored boundary, so a lower (replayed / clock-skewed) epoch can never move
  // the boundary backwards and re-open a revoked window.
  var validFromExpr = "CASE WHEN " + refs.proposed("validFromEpoch") + " > " +
    refs.existing("validFromEpoch") + " THEN " + refs.proposed("validFromEpoch") +
    " ELSE " + refs.existing("validFromEpoch") + " END";
  var built = sql.upsert(t, _sessionSqlOpts())
    .columns(["subjectHash", "validFromEpoch", "updatedAt"])
    .values({ subjectHash: subjectHash, validFromEpoch: epochMs, updatedAt: Date.now() })
    .onConflict(["subjectHash"])
    .doUpdate({ validFromEpoch: validFromExpr, updatedAt: "?" }, [Date.now()])
    .returning(["validFromEpoch"])
    .toSql();
  // The valid-from boundary is a FRAMEWORK table (FRAMEWORK_SCHEMA / cluster
  // DDL), NOT session data — it executes against clusterStorage (the framework
  // db) whenever one is initialized, never _currentStore(). When the framework
  // db is NOT initialized but an operator store IS configured (a store-backed-
  // only b.session.useStore deployment that never ran b.db.init()), the boundary
  // falls back to that store — provisioned on demand — so logout-everywhere
  // still raises the stateless boundary instead of throwing db/not-initialized
  // (#340). _runValidFrom resolves the target; never silently drops the boundary
  // when a db is present, and propagates db/not-initialized when neither exists.
  var row = await _runValidFrom(async function (target) {
    if (built.readbackSql) {
      // MySQL: ON DUPLICATE KEY UPDATE has no RETURNING — run the upsert, then
      // the readback SELECT b.sql emits (keyed on subjectHash). MySQL only ever
      // runs against the framework cluster db; the localDbThin fallback store is
      // sqlite (RETURNING), so this branch never routes through it.
      await target.execute(built.sql, built.params);
      var readback = await target.execute(built.readbackSql.sql, built.readbackSql.params);
      return readback.rows && readback.rows[0];
    }
    var result = await target.execute(built.sql, built.params);
    return result.rows && result.rows[0];
  });
  var effective = row ? Number(row.validFromEpoch) : epochMs;

  // Best-effort audit — matches the file's emit convention (safeEmit is
  // already drop-silent internally).
  try {
    audit.safeEmit({
      action:   "auth.session.valid_from_bump",
      outcome:  "success",
      metadata: { validFromEpoch: effective },
    });
  } catch (_ignored) { /* audit best-effort */ }

  return effective;
}

/**
 * @primitive b.session.validFrom
 * @signature b.session.validFrom(subjectId)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.bump, b.session.check
 *
 * Read the current valid-from boundary (epoch ms) for a subject. Returns `0`
 * when the subject has never been bumped — no token is revoked by boundary, so
 * any non-negative token `iat` passes `b.session.check`. Runs anywhere (leader
 * or follower) — it only reads. The subject id is hashed before lookup; the
 * plaintext id never lands in the table.
 *
 * @example
 *   var boundary = await b.session.validFrom("user-42");
 *   // → 1735689600000  (last bump)   or   0  (never bumped)
 */
async function validFrom(subjectId) {
  if (typeof subjectId !== "string" || subjectId.length === 0) return 0;
  var built = sql.select(_validFromSqlTable(), _sessionSqlOpts())
    .columns(["validFromEpoch"])
    .where("subjectHash", _hashSubjectId(subjectId))
    .toSql();
  // Framework valid-from table — read from clusterStorage (the framework db)
  // when one is initialized, falling back to the configured store only when it
  // is not (the same store bump() wrote the boundary to in a store-backed-only
  // deployment). _runValidFrom keeps the read on the SAME backend the write
  // chose, so a boundary raised via destroyAllForUser/bump is the one read back
  // here. See bump() for the full rationale (#340).
  var row = await _runValidFrom(async function (target) {
    var result = await target.execute(built.sql, built.params);
    return result.rows && result.rows.length > 0 ? result.rows[0] : null;
  });
  return row ? Number(row.validFromEpoch) : 0;
}

/**
 * @primitive b.session.check
 * @signature b.session.check(subjectId, tokenIatMs)
 * @since     0.15.13
 * @status    stable
 * @related   b.session.bump, b.session.validFrom
 *
 * Decide whether a stateless self-validating token is still valid against the
 * subject's valid-from boundary. Returns `true` when the token's issued-at
 * (`tokenIatMs`, epoch ms) is at or after the boundary; `false` when the token
 * was issued before the last `bump` (revoked). A subject that was never bumped
 * has boundary `0`, so any non-negative `iat` is valid. Runs anywhere.
 *
 * Fails CLOSED: a non-finite / negative / non-number `tokenIatMs` returns
 * `false` (treat an unparseable token as revoked rather than admit it). Call
 * this AFTER the token's own signature + expiry checks pass — it is the
 * server-side revocation layer those stateless checks otherwise lack.
 *
 * @example
 *   // jwt already signature- and exp-verified; iat is in seconds → ms:
 *   var ok = await b.session.check(claims.sub, claims.iat * 1000);
 *   if (!ok) { res.statusCode = 401; res.end("session revoked"); return; }
 */
async function check(subjectId, tokenIatMs) {
  if (typeof tokenIatMs !== "number" || !isFinite(tokenIatMs) || tokenIatMs < 0) {
    return false;
  }
  var boundary = await validFrom(subjectId);
  return tokenIatMs >= boundary;
}

module.exports = {
  create:               create,
  verify:               verify,
  destroy:              destroy,
  logout:               logout,
  destroyAllForUser:    destroyAllForUser,
  touch:                touch,
  rotate:               rotate,
  updateData:           updateData,
  purgeExpired:         purgeExpired,
  count:                count,
  bump:                 bump,
  validFrom:            validFrom,
  check:                check,
  useStore:             useStore,
  isAnonymous:          isAnonymous,
  stores:               require("./session-stores"),                                              // allow:inline-require — session-stores depends on local-db-thin which requires audit lazily; eager require is fine here
  DEFAULT_TTL_MS:       DEFAULT_TTL_MS,
  ANON_PREFIX:          ANON_PREFIX,
  _resetForTest:        _resetForTest,
};
