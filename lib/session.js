/**
 * Session — thin facade over `b.session` backed by a tmpfs SQLite
 * store via `b.session.stores.localDbThin`.
 *
 * Why `b.session`: the framework's session primitive carries the same
 * vault-sealed-cookie envelope HermitStash had hand-rolled (ML-KEM-1024
 * + P-384 hybrid + XChaCha20-Poly1305 via `b.vault.seal`), the same
 * `/24` IPv4 + `/64` IPv6 fingerprint binding (via the
 * `clientIpPrefix` field), and the same idle-timeout semantics. v0.8.66
 * landed `b.session.updateData` — the missing primitive that makes the
 * full migration tractable. Earlier versions exposed only `touch` (no
 * data persist) and `rotate` (rotates the sid, breaking cookie
 * continuity), so HS had no way to flush per-request session.data
 * mutations back to storage between requests.
 *
 * Why a separate tmpfs SQLite file (instead of `_blamejs_sessions` in
 * the main DB): session writes on every request would fight the main
 * DB's WAL fsync + 5-minute encrypt-at-rest re-flush cycle. Routing
 * session writes to a dedicated tmpfs file (default `/dev/shm`) keeps
 * them RAM-fast and out of the encrypted-at-rest snapshot.
 *
 * On-the-wire cookie shape: HS strips the leading `vault:` envelope
 * prefix from the cookie value to save bytes (`b.session.create`
 * returns the prefixed token; we strip on Set-Cookie and re-add before
 * `b.session.verify`). The actual sealed payload is identical to what
 * `b.session` produces by default — same ciphertext, same envelope
 * version. The sid INSIDE the envelope is also the same shape (32-byte
 * hex token).
 *
 * Anonymous sessions: HS creates a session for every visitor on the
 * first request (so CSRF tokens, OAuth state, passkey challenges all
 * have a place to live before login). `b.session.create` requires a
 * `userId`, so anonymous visitors get `userId = "anon:<random>"`. On
 * login, `req.regenerateSession({ userId })` destroys the anonymous
 * session and creates a new one with the real user id, copying the
 * existing session.data forward — preventing session-fixation attacks
 * while keeping pre-login CSRF state continuous.
 *
 * Storage migration on upgrade: pre-v1.9.29 sessions lived in HS's
 * `sessions` table with raw-sid PK. v1.9.29+ uses
 * `b.session.stores.localDbThin`'s `_blamejs_sessions` table with
 * sha3-hashed sid PK. The two are incompatible, so existing sessions
 * are invalidated on the upgrade boot — every user re-authenticates
 * once. Pre-v1 framework, no compat shim ships.
 */
"use strict";

var nodePath = require("node:path");
var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var config = require("./config");
var clientIp = require("./client-ip");
var { TIME, DATA_DIR: _dataDir } = require("./constants");
var C = require("./constants");

var COOKIE_NAME      = "hs_sid";
var MAX_AGE          = TIME.days(7);
var DEFAULT_IDLE_MS  = TIME.minutes(30);

// Operator-tunable knobs surfaced as env vars (admin → Branding can
// expose later). Defaults match the framework's recommended posture
// for HS's threat model — strict /24+/64 subnet binding, no absolute
// timeout (TTL = MAX_AGE bounds lifetime).
function _resolveFingerprintFields() {
  var raw = b.safeEnv.readVar("SESSION_FINGERPRINT_FIELDS");
  if (!raw) return ["clientIpPrefix", "userAgent"];
  return raw.split(",").map(function (f) { return f.trim(); }).filter(Boolean);
}
function _resolveAbsoluteTimeoutMs() {
  var raw = parseInt(b.safeEnv.readVar("SESSION_ABSOLUTE_TIMEOUT_MS") || "", 10);
  return Number.isFinite(raw) && raw >= 0 ? raw : 0;
}
var FINGERPRINT_FIELDS    = _resolveFingerprintFields();
var ABSOLUTE_TIMEOUT_MS   = _resolveAbsoluteTimeoutMs();

// Resolve tmpfs preference for the sessions DB.
var _tmpDir = b.safeEnv.readVar("HERMITSTASH_TMPDIR")
  || (nodeFs.existsSync("/dev/shm") ? "/dev/shm" : _dataDir);
var sessionDbPath = nodePath.join(_tmpDir, b.safeEnv.readVar("HERMITSTASH_SESSION_DB") || "hermitstash-sessions.db");

// Harden the file mode on Unix (owner-only). Best-effort — Windows
// has no equivalent, file permissions are governed by ACLs.
try {
  if (process.platform !== "win32") {
    nodeFs.writeFileSync(sessionDbPath, "", { flag: "a", mode: 0o600 });
  }
} catch (_e) { /* file pre-existing or fs error — non-fatal */ }

// Wire the framework session primitive at module-load time. Subsequent
// b.session.{create, verify, ...} calls go to this store.
var _sessionStore = b.session.stores.localDbThin({ file: sessionDbPath });
b.session.useStore(_sessionStore);

// Register the _blamejs_sessions schema with cryptoField. b.db.init
// would do this automatically as part of FRAMEWORK_SCHEMA, but we're
// not calling b.db.init for sessions (HS owns its main DB lifecycle).
// Without this, b.session.destroyAllForUser fails with "_blamejs_sessions
// schema is missing the userIdHash derived hash" because cryptoField
// can't compute the hash without the schema entry. Mirrors
// lib/vendor/blamejs/lib/db.js's FRAMEWORK_SCHEMA `_blamejs_sessions`
// table definition byte-for-byte — keep these in sync if blamejs
// extends the schema.
b.cryptoField.registerTable("_blamejs_sessions", {
  sealedFields:  ["userId", "data"],
  derivedHashes: { userIdHash: { from: "userId" } },
});

// Delegate to b.cookies.parseSafe — gains bounded parsing (header /
// name / value byte caps default to 8 KiB / 1 KiB / 4 KiB) + a null-
// prototype output object that defends against __proto__ /
// constructor / prototype cookie-name pollution before the
// hasOwnProperty gate in callers. Pre-this-swap the hand-rolled
// version returned a plain {} with no bounds; an attacker-controlled
// Cookie header could pollute the prototype chain or burn CPU on a
// pathological payload.
//
// parseSafe returns { jar, ... }; jar is the name→value map. parseSafe
// also URL-decodes values automatically (so consumers must NOT call
// decodeURIComponent again — the value at the read site is already
// the canonical token).
function parseCookies(req) {
  return b.cookies.parseSafe(req.headers.cookie || "").jar;
}

function _anonUserId() {
  return "anon:" + b.crypto.generateToken(C.BYTES.bytes(16));
}

// Cookie value is the framework-emitted token verbatim (vault:-
// prefixed envelope). Pre-v1.9.30 HS stripped the prefix to save 7
// wire bytes — that strip-and-restore dance is gone now; framework-
// shape parity wins over the byte savings. Existing pre-v1.9.30
// cookies don't have the prefix and naturally fail b.session.verify
// on first request after upgrade — affected users re-authenticate.
function _setSessionCookie(res, token) {
  var secure = config.rpOrigin && config.rpOrigin.startsWith("https") ? "; Secure" : "";
  var cookie = COOKIE_NAME + "=" + encodeURIComponent(token)
             + "; Path=/; HttpOnly; SameSite=Lax" + secure
             + "; Max-Age=" + (MAX_AGE / C.TIME.seconds(1));
  var existing = res.getHeader("Set-Cookie") || [];
  var arr = Array.isArray(existing) ? existing : (existing ? [existing] : []);
  // Drop any previous Set-Cookie for hs_sid we wrote (regenerate path)
  // so the response only carries the latest token.
  arr = arr.filter(function (c) { return !c.startsWith(COOKIE_NAME + "="); });
  arr.push(cookie);
  res.setHeader("Set-Cookie", arr);
}

// ---- middleware ----

async function sessionMiddleware(req, res, next) {
  try {
    var idleTimeoutMs = config.sessionIdleTimeout || DEFAULT_IDLE_MS;

    // Track the live token in closure scope so res.writeHead and
    // req.regenerateSession see the most recent value after a rotation.
    var token = null;

    var cookies = parseCookies(req);
    if (cookies[COOKIE_NAME]) {
      // parseCookies (b.cookies.parseSafe) already URL-decodes — no
      // second decodeURIComponent here.
      var candidateToken = cookies[COOKIE_NAME];
      var verified = await b.session.verify(candidateToken, {
        req: req,
        idleTimeoutMs: idleTimeoutMs,
        absoluteTimeoutMs: ABSOLUTE_TIMEOUT_MS,
        fingerprintFields: FINGERPRINT_FIELDS,
        requireFingerprintMatch: true,         // hard-kill on UA / IP-prefix drift
        clientIpResolver: clientIp.getIp,      // proxy-aware IP so clientIpPrefix is stable behind nginx/Docker
      });
      if (verified) {
        token = candidateToken;
        req.session = verified.data || {};
      }
    }

    if (!token) {
      // No cookie / expired / drift / unknown → fresh anonymous session.
      var created = await b.session.create({
        userId: _anonUserId(),
        ttlMs: MAX_AGE,
        data: {},
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
        clientIpResolver: clientIp.getIp,
      });
      token = created.token;
      req.session = {};
    }

    req.sessionId = token;

    // Login + 2FA pending + 2FA complete all rotate the sid to defeat
    // session-fixation. Use destroy + create so the new userId is bound
    // at the storage layer (b.session.rotate keeps the existing userId,
    // which would leave the row glued to the anonymous identity).
    req.regenerateSession = async function (opts) {
      opts = opts || {};
      var carriedData = Object.assign({}, req.session);
      // Strip the framework's reserved fingerprint key so create() can
      // re-derive it from req.headers + the new sid (its own salt).
      delete carriedData.__bj_fingerprint;
      var newUserId = opts.userId || _anonUserId();
      try { await b.session.destroy(token); } catch (_e) { /* old token already gone — proceed */ }
      var created2 = await b.session.create({
        userId: newUserId,
        ttlMs: MAX_AGE,
        data: carriedData,
        req: req,
        fingerprintFields: FINGERPRINT_FIELDS,
        clientIpResolver: clientIp.getIp,
      });
      token = created2.token;
      req.session = carriedData;
      req.sessionId = token;
    };

    // Persist any req.session mutations + bump lastActivity + (re)set
    // the cookie before the response goes out. Two hook points:
    //
    //   - writeHead wraps to set the cookie and capture status/headers
    //     synchronously (the route may call res.write before res.end,
    //     so headers must be committed early). The cookie write is
    //     synchronous; only the SQL flush is deferred.
    //
    //   - end wraps to await the b.session.updateData + .touch flush
    //     BEFORE calling origEnd. Without this delay, the next request
    //     can land on the server before the previous request's session
    //     mutations are persisted, so verify() reads stale data and
    //     downstream middleware (api-encrypt's apiKey handshake, csrf-
    //     policy's _csrf token) re-creates the field, breaking the
    //     same-session continuity the test client expects.
    var origWriteHead = res.writeHead.bind(res);
    res.writeHead = function (statusCode, ...rest) {
      // On a logout response, secureLogout() has already queued the
      // Max-Age=0 hs_sid cookie + Clear-Site-Data header. Re-setting the
      // live ~7-day cookie here would clobber that expiry and leave the
      // browser holding a cookie for a session row that no longer exists.
      // Skip ONLY the cookie re-set; status + the rest of the head still
      // pass through unchanged.
      if (!res._sessionLoggedOut) {
        _setSessionCookie(res, token);
      }
      return origWriteHead(statusCode, ...rest);
    };
    var origEnd = res.end.bind(res);
    res.end = function (chunk, encoding, callback) {
      if (typeof chunk === "function") { callback = chunk; chunk = undefined; encoding = undefined; }
      else if (typeof encoding === "function") { callback = encoding; encoding = undefined; }
      Promise.all([
        b.session.updateData(token, req.session).catch(function (_e) { /* persist best-effort */ }),
        b.session.touch(token, { extendBy: MAX_AGE }).catch(function (_e) { /* lastActivity best-effort */ }),
      ]).then(function () {
        if (chunk !== undefined) origEnd(chunk, encoding, callback);
        else if (callback) origEnd(callback);
        else origEnd();
      });
      return res;
    };

    next();
  } catch (err) {
    next(err);
  }
}

// ---- HS API surface (unchanged shape; routes unchanged) ----

async function clearSessionsForUser(userId) {
  if (!userId) return 0;
  try {
    return await b.session.destroyAllForUser(userId);
  } catch (e) {
    // b.session.destroyAllForUser DELETEs the store-backed session rows first,
    // then bumps a per-subject stateless "valid-from" boundary in the framework
    // cluster DB (b.db). HS owns its own DB lifecycle, never calls b.db.init, and
    // verifies every session through the store (no stateless cookies/JWTs), so
    // that bump targets an uninitialized framework DB and throws db/not-initialized.
    // Every session HS actually has is already revoked by the DELETE above when
    // that throw happens, so this one specific post-revocation failure is safe to
    // absorb — the stateless boundary is a no-op for HS's session model. Any OTHER
    // error means the revocation itself failed and MUST propagate.
    //
    // blamejs 0.15.x no longer surfaces the raw "db/not-initialized" here: it
    // catches that bump failure and re-throws it as a SessionError with code
    // "MISCONFIGURED" whose message describes the stateless valid-from boundary
    // ("...the store-backed rows were already deleted..."). Match that re-wrap by
    // its distinctive message so the swallow still fires — but NOT the other
    // "MISCONFIGURED" throw (the userIdHash derived-hash schema is not
    // registered), which is a genuine misconfiguration that must propagate.
    if (e && (
      e.code === "db/not-initialized" ||
      (e.code === "MISCONFIGURED" &&
        /valid-from boundary|stateless valid-from|store-backed rows were already deleted/i.test(e.message || ""))
    )) return 0;
    throw e;
  }
}

async function clearSessionById(token) {
  if (!token) return false;
  try { return await b.session.destroy(token); }
  catch (_e) { return false; }
}

// Secure self-logout: destroy the storage row AND tell the browser to
// drop its client-side state. b.session.logout emits an RFC 9527
// Clear-Site-Data header (cookies + storage + cache + executionContexts)
// and an expired hs_sid Set-Cookie, then revokes the row — same destroy
// path clearSessionById drives, but it also reaches the live response so
// stale tabs can't replay the now-revoked cookie.
//
// res._sessionLoggedOut suppresses the sessionMiddleware writeHead cookie
// re-set on this response: without it the middleware would re-emit a live
// ~7-day hs_sid cookie that clobbers the Max-Age=0 expiry written here.
// cookieName MUST be COOKIE_NAME (hs_sid) — b.session.logout defaults to
// "sid", which would expire the wrong cookie and leave hs_sid live.
async function secureLogout(res, token) {
  if (res) res._sessionLoggedOut = true;
  if (!token) return false;
  try { return await b.session.logout(res, token, { cookieName: COOKIE_NAME }); }
  catch (_e) { return false; }
}

async function clearAllSessions() {
  // b.session has no purge-all primitive; the operator-shape "revoke
  // every session" requires a direct table delete. Hitting the
  // localDbThin store here is fine — it's the only consumer of this
  // file and the schema is owned by `b.session`.
  await _sessionStore.execute("DELETE FROM _blamejs_sessions", []);
  return true;
}

async function getSessionData(token) {
  if (!token) return null;
  try {
    var verified = await b.session.verify(token, {});
    return verified ? (verified.data || null) : null;
  } catch (_e) {
    return null;
  }
}

module.exports = {
  sessionMiddleware:    sessionMiddleware,
  parseCookies:         parseCookies,
  clearSessionsForUser: clearSessionsForUser,
  clearSessionById:     clearSessionById,
  secureLogout:         secureLogout,
  clearAllSessions:     clearAllSessions,
  getSessionData:       getSessionData,
};
