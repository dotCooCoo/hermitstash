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
var cluster = require("./cluster");
var clusterStorage = require("./cluster-storage");
var C = require("./constants");
var { generateToken, sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var safeJson = require("./safe-json");
var { SessionError } = require("./framework-error");

// vault is initialized at boot before sessions; lazyRequire keeps the
// load order independent of module-import order. Used to seal/unseal
// the cookie-side sid so the wire token is ciphertext rather than
// plaintext (sealed-cookie default since v0.8.61).
var vault = lazyRequire(function () { return require("./vault"); });

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

// Column order used for INSERT — kept as a constant so the placeholders
// list and the values list stay in sync. Must match _blamejs_sessions's
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
  var sealed = cryptoField.sealRow("_blamejs_sessions", row);
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
// public client IP every few requests as the device hops cells, so a
// strict full-IP fingerprint logs out healthy mobile users. The
// "clientIpPrefix" field hashes a /24 mask for IPv4 (256-address bucket
// — same Class C-shaped neighborhood) and a /64 mask for IPv6 (the IPv6
// "site" prefix the RIRs allocate to every ISP customer). Drift across
// /24 OR /64 is meaningfully suspicious; drift within is not.
//
// Per the IPv6 addressing architecture (RFC 4291 §2.5.4) every customer
// LAN is assigned at least a /64; tightening below /64 punishes IPv6
// privacy-extension address rotation. /24 IPv4 is the original
// IP-geolocation bucket size and matches the legacy carrier-NAT pool
// stride. Operators with stricter needs pass a function-form
// fingerprint field for custom mask widths.
//
// Protocol constants — named so the bit-arithmetic stays readable.
var IP_BITS_PER_BYTE      = 8;                                                                  // allow:raw-byte-literal — bits per byte; protocol constant, not a byte size
var IPV4_OCTET_COUNT      = 4;
var IPV4_OCTET_RANGE      = 256;                                                                // allow:raw-byte-literal — 0..255 inclusive; v4 octet domain
var IPV4_TOTAL_BITS       = 32;                                                                 // allow:raw-byte-literal — IPv4 address width in bits
var IPV4_DEFAULT_PREFIX   = 24;                                                                 // allow:raw-byte-literal — /24 carrier-NAT pool stride
var IPV6_GROUP_COUNT      = 8;                                                                  // allow:raw-byte-literal — 8 16-bit groups in v6
var IPV6_BYTE_COUNT       = 16;                                                                 // allow:raw-byte-literal — 16 bytes in v6
var IPV6_DEFAULT_PREFIX   = 64;                                                                 // allow:raw-byte-literal — /64 customer LAN per RFC 4291 §2.5.4
var BYTE_MASK             = 0xff;
var HEX_RADIX             = 16;                                                                 // allow:raw-byte-literal — base-16 radix
var V4_MAPPED_V6_PREFIX   = "::ffff:";

function _maskIpv4(ip, prefix) {
  // ip = "a.b.c.d"; prefix is bits to keep (1..32).
  var parts = String(ip).split(".");
  if (parts.length !== IPV4_OCTET_COUNT) return null;
  var n = 0;
  for (var i = 0; i < IPV4_OCTET_COUNT; i++) {
    var oct = parseInt(parts[i], 10);
    if (!Number.isInteger(oct) || oct < 0 || oct >= IPV4_OCTET_RANGE) return null;
    n = (n * IPV4_OCTET_RANGE) + oct;
  }
  // Apply prefix mask.
  var mask = prefix === 0 ? 0 : (-1 >>> (IPV4_TOTAL_BITS - prefix)) << (IPV4_TOTAL_BITS - prefix);
  // Bitwise on 32-bit unsigned. JS coerces to 32-bit signed, so use
  // unsigned right shift to recover.
  var masked = (n & mask) >>> 0;
  return ((masked >>> IP_BITS_PER_BYTE * 3) & BYTE_MASK) + "." +
         ((masked >>> IP_BITS_PER_BYTE * 2) & BYTE_MASK) + "." +
         ((masked >>> IP_BITS_PER_BYTE)     & BYTE_MASK) + "." +
         (masked & BYTE_MASK) + "/" + prefix;
}

function _maskIpv6(ip, prefix) {
  // Expand to 8 16-bit groups. Accept :: shorthand. Reject if invalid.
  var raw = String(ip).toLowerCase();
  // Strip an embedded zone id (fe80::1%eth0); not part of the address.
  var pct = raw.indexOf("%");
  if (pct !== -1) raw = raw.substring(0, pct);
  var doubleColonAt = raw.indexOf("::");
  var groups;
  if (doubleColonAt === -1) {
    groups = raw.split(":");
    if (groups.length !== IPV6_GROUP_COUNT) return null;
  } else {
    var left = raw.substring(0, doubleColonAt).split(":");
    var right = raw.substring(doubleColonAt + 2).split(":");
    if (left.length === 1 && left[0] === "") left = [];
    if (right.length === 1 && right[0] === "") right = [];
    var fillCount = IPV6_GROUP_COUNT - left.length - right.length;
    if (fillCount < 0) return null;
    var middle = [];
    for (var fi = 0; fi < fillCount; fi++) middle.push("0");
    groups = left.concat(middle).concat(right);
  }
  // Each group is 1–4 hex chars.
  var bytes = [];
  for (var gi = 0; gi < IPV6_GROUP_COUNT; gi++) {
    var g = groups[gi];
    if (typeof g !== "string" || g.length === 0 || g.length > 4 || /[^0-9a-f]/.test(g)) return null;
    var v = parseInt(g, HEX_RADIX);
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) return null;
    bytes.push((v >> IP_BITS_PER_BYTE) & BYTE_MASK);
    bytes.push(v & BYTE_MASK);
  }
  // Apply prefix in bits.
  var keepBytes = Math.floor(prefix / IP_BITS_PER_BYTE);
  var keepBits  = prefix % IP_BITS_PER_BYTE;
  for (var bi = 0; bi < IPV6_BYTE_COUNT; bi++) {
    if (bi < keepBytes) continue;
    if (bi === keepBytes && keepBits > 0) {
      var m = (BYTE_MASK << (IP_BITS_PER_BYTE - keepBits)) & BYTE_MASK;
      bytes[bi] = bytes[bi] & m;
    } else {
      bytes[bi] = 0;
    }
  }
  // Re-emit as colon-hex (no compression — deterministic for hashing).
  var out = [];
  for (var oi = 0; oi < IPV6_BYTE_COUNT; oi += 2) {
    out.push(((bytes[oi] << IP_BITS_PER_BYTE) | bytes[oi + 1]).toString(HEX_RADIX));
  }
  return out.join(":") + "/" + prefix;
}

function _ipPrefix(ip) {
  if (typeof ip !== "string" || ip.length === 0) return "";
  // IPv4-mapped IPv6 (::ffff:1.2.3.4) — strip the wrapper so the v4
  // mask applies. Same bucket regardless of how the proxy reported it.
  var lower = ip.toLowerCase();
  if (lower.indexOf(V4_MAPPED_V6_PREFIX) === 0 && lower.indexOf(".") !== -1) {
    return _maskIpv4(lower.substring(V4_MAPPED_V6_PREFIX.length), IPV4_DEFAULT_PREFIX) || "";
  }
  if (ip.indexOf(":") !== -1) return _maskIpv6(ip, IPV6_DEFAULT_PREFIX) || "";
  if (ip.indexOf(".") !== -1) return _maskIpv4(ip, IPV4_DEFAULT_PREFIX) || "";
  return "";
}

function _buildFingerprintInputs(req, fields) {
  if (!req) return null;
  var headers = req.headers || {};
  var inputs = {};
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    if (f === "clientIp") {
      inputs.clientIp = requestHelpers.clientIp(req) || "";
    } else if (f === "clientIpPrefix") {
      // /24 v4 + /64 v6 — see _ipPrefix() commentary.
      inputs.clientIpPrefix = _ipPrefix(requestHelpers.clientIp(req) || "");
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
  var fpInputs = _buildFingerprintInputs(opts.req, fpFields);
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
  var values = SESSION_COLS.map(function (c) { return sealed[c]; });
  var placeholders = SESSION_COLS.map(function () { return "?"; }).join(", ");
  var quoted = SESSION_COLS.map(function (c) { return '"' + c + '"'; }).join(", ");
  await _currentStore().execute(
    "INSERT INTO _blamejs_sessions (" + quoted + ") VALUES (" + placeholders + ")",
    values
  );

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
async function verify(token, verifyOpts) {
  if (typeof token !== "string" || token.length === 0) return null;
  verifyOpts = verifyOpts || {};
  // Sealed-cookie default — unseal the wire token to recover the sid.
  // Pre-v0.8.61 raw cookies / tampered envelopes return null and the
  // caller re-auths. The plaintext sid never leaves this function.
  var sid = _unsealCookieToken(token);
  if (sid === null) return null;
  var sidHash = _hashSid(sid);

  var row = await _currentStore().executeOne(
    "SELECT sidHash, userId, userIdHash, data, createdAt, expiresAt, lastActivity " +
    "FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
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
  var idleMs = verifyOpts.idleTimeoutMs !== undefined
    ? verifyOpts.idleTimeoutMs : DEFAULT_IDLE_TIMEOUT_MS;
  var absMs = verifyOpts.absoluteTimeoutMs !== undefined
    ? verifyOpts.absoluteTimeoutMs : DEFAULT_ABSOLUTE_TIMEOUT_MS;
  if (idleMs > 0) {
    var lastActivity = Number(row.lastActivity);
    if ((nowMs - lastActivity) > idleMs) {
      try {
        audit.safeEmit({
          action: "auth.session.expired_idle", outcome: "success",
          metadata: { idleMs: nowMs - lastActivity, threshold: idleMs },
        });
      } catch (_ignored) { /* audit best-effort */ }
      if (cluster.isLeader()) {
        try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
      }
      return null;
    }
  }
  if (absMs > 0) {
    var createdAt = Number(row.createdAt);
    if ((nowMs - createdAt) > absMs) {
      try {
        audit.safeEmit({
          action: "auth.session.expired_absolute", outcome: "success",
          metadata: { ageMs: nowMs - createdAt, threshold: absMs },
        });
      } catch (_ignored) { /* audit best-effort */ }
      if (cluster.isLeader()) {
        try { await _deleteBySidHash(sidHash); } catch (_e) { /* best-effort */ }
      }
      return null;
    }
  }
  // Unseal sealed columns (userId, data) using the cryptoField pipeline
  // so we return cleartext to the caller — same shape as the previous
  // db().from(...).first() path delivered.
  var unsealed = cryptoField.unsealRow("_blamejs_sessions", row);
  var data = null;
  var storedFingerprint = null;
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
  if (storedFingerprint && verifyOpts.req) {
    var fpFields = Array.isArray(verifyOpts.fingerprintFields) && verifyOpts.fingerprintFields.length > 0
      ? verifyOpts.fingerprintFields : DEFAULT_FINGERPRINT_FIELDS;
    var currentInputs = _buildFingerprintInputs(verifyOpts.req, fpFields);
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

async function _deleteBySidHash(sidHash) {
  var result = await _currentStore().execute(
    "DELETE FROM _blamejs_sessions WHERE sidHash = ?",
    [sidHash]
  );
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
  var lookup = cryptoField.lookupHash("_blamejs_sessions", "userId", userId);
  if (!lookup) {
    throw _err("MISCONFIGURED",
      "_blamejs_sessions schema is missing the userIdHash derived hash — framework misconfigured",
      true);
  }
  var result = await _currentStore().execute(
    "DELETE FROM _blamejs_sessions WHERE userIdHash = ?",
    [lookup.value]
  );
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
    var result = await _currentStore().execute(
      "UPDATE _blamejs_sessions SET lastActivity = ?, expiresAt = ? " +
      "WHERE sidHash = ? AND expiresAt >= ?",
      [nowMs, newExpires, sidHash, nowMs]
    );
    return (result.rowCount || 0) > 0;
  }
  var result2 = await _currentStore().execute(
    "UPDATE _blamejs_sessions SET lastActivity = ? " +
    "WHERE sidHash = ? AND expiresAt >= ?",
    [nowMs, sidHash, nowMs]
  );
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
 * @opts
 *   {
 *     data?:   object,     // replacement session data (re-sealed)
 *     ttlMs?:  number,     // new TTL; if absent, existing expiresAt preserved
 *     reason?: string,     // audit metadata ("login", "mfa", "role-change")
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

  var setParts = ['"sidHash" = ?', '"lastActivity" = ?'];
  var setParams = [newSidHash, nowMs];

  if (opts.data !== undefined) {
    var dataJson = opts.data ? JSON.stringify(opts.data) : null;
    var sealedRow = cryptoField.sealRow("_blamejs_sessions", { data: dataJson });
    setParts.push('"data" = ?');
    setParams.push(sealedRow.data);
  }
  if (newExpires !== null) {
    setParts.push('"expiresAt" = ?');
    setParams.push(newExpires);
  }

  var sql = "UPDATE _blamejs_sessions SET " + setParts.join(", ") +
            " WHERE sidHash = ? AND expiresAt >= ?";
  var params = setParams.concat([oldSidHash, nowMs]);
  var result = await _currentStore().execute(sql, params);
  if ((result.rowCount || 0) === 0) return null;

  // Read the row's effective expiresAt to return — single source of truth.
  var row = await _currentStore().executeOne(
    'SELECT "expiresAt" FROM _blamejs_sessions WHERE sidHash = ?',
    [newSidHash]
  );
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
  var row = await _currentStore().executeOne(
    'SELECT "userId", "userIdHash", "data", "createdAt", "expiresAt", "lastActivity" ' +
    'FROM _blamejs_sessions WHERE sidHash = ? AND expiresAt >= ?',
    [sidHash, nowMs]
  );
  if (!row) return false;

  // Recover the existing data + reserved fingerprint key (vault-
  // sealed at rest). Operators that want a fresh fingerprint also
  // call b.session.rotate; updateData preserves the binding.
  var unsealed = cryptoField.unsealRow("_blamejs_sessions", row);
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
  var sealedRow = cryptoField.sealRow("_blamejs_sessions", {
    data: next ? JSON.stringify(next) : null,
  });

  var setParts = ['"data" = ?'];
  var setParams = [sealedRow.data];
  if (opts.touchLastActivity !== false) {
    setParts.push('"lastActivity" = ?');
    setParams.push(nowMs);
  }
  var sql = "UPDATE _blamejs_sessions SET " + setParts.join(", ") +
            " WHERE sidHash = ? AND expiresAt >= ?";
  var result = await _currentStore().execute(sql, setParams.concat([sidHash, nowMs]));
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
  var result = await _currentStore().execute(
    "DELETE FROM _blamejs_sessions WHERE expiresAt < ?",
    [Date.now()]
  );
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
  var row = await _currentStore().executeOne(
    "SELECT COUNT(*) AS c FROM _blamejs_sessions WHERE expiresAt >= ?",
    [Date.now()]
  );
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
  if (typeof store !== "object" ||
      typeof store.execute    !== "function" ||
      typeof store.executeOne !== "function") {
    throw _err("INVALID_ARG",
      "session.useStore: store must expose execute(sql,params) and executeOne(sql,params)", true);
  }
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

module.exports = {
  create:               create,
  verify:               verify,
  destroy:              destroy,
  destroyAllForUser:    destroyAllForUser,
  touch:                touch,
  rotate:               rotate,
  updateData:           updateData,
  purgeExpired:         purgeExpired,
  count:                count,
  useStore:             useStore,
  isAnonymous:          isAnonymous,
  stores:               require("./session-stores"),                                              // allow:inline-require — session-stores depends on local-db-thin which requires audit lazily; eager require is fine here
  DEFAULT_TTL_MS:       DEFAULT_TTL_MS,
  ANON_PREFIX:          ANON_PREFIX,
  _resetForTest:        _resetForTest,
};
