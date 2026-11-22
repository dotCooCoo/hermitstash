/**
 * OpenID Connect sign-in for the Google button and the generic OIDC button.
 *
 * Both providers run on b.auth.oauth: discovery, PKCE S256, state, nonce, the
 * RFC 9207 iss check, and id_token signature, issuer, audience and expiry
 * checks all happen there. This module builds one client per provider, drops
 * every client on a config reload, stores the per-login state in the session,
 * and turns a verified callback into an identity record:
 *
 *   { provider, issuer, sub, email, displayName, avatar, groups }
 *
 * `email` is set only when the provider marks it verified with the boolean
 * `email_verified: true`. `groups` is an array of strings, or null when the
 * provider did not supply the claim in the id_token or in userinfo.
 *
 * Every failure is an Error carrying `oidcReason`, a short fixed string that is
 * safe to write to the audit log. Error messages from the OAuth layer can quote
 * a provider response body, so callers log the reason and never the message.
 */
var b = require("./vendor/blamejs");
var config = require("./config");
var C = require("./constants");
var oidcPolicy = require("./oidc-policy");

var STATE_MAX_AGE_MS = C.TIME.minutes(5);
var MAX_SUB_LENGTH = 255;
var MAX_EMAIL_LENGTH = 254;
var MAX_DISPLAY_NAME_LENGTH = 100;
var MAX_AVATAR_LENGTH = C.BYTES.kib(2);
var MAX_GROUPS = 1000; // allow:raw-byte-literal — entry-count cap, not a byte size
var MAX_GROUP_LENGTH = 256; // allow:raw-byte-literal — character cap on one group name
var MAX_AUTH_URL_LENGTH = C.BYTES.kib(8);
var MAX_ERROR_CODE_LENGTH = 80;
var MAX_OP_ERROR_LENGTH = 40;
var MAX_AUDIT_REASON_LENGTH = 120; // allow:raw-byte-literal allow:raw-time-literal — character cap, not a size or duration
var ERROR_CODE_RE = /^[a-z0-9\-]+\/[a-z0-9\-\/]+$/;
var DEFAULT_SCOPES = ["openid", "email", "profile"];

// Session keys for the pending login. Google keeps the key it has always used.
var STATE_KEYS = Object.freeze({ google: "oauthState", oidc: "oidcState" });

var CONTROL_STRIP_RE = /[\x00-\x1F\x7F]/g;
var CONTROL_TEST_RE = /[\x00-\x1F\x7F]/;

var _clients = Object.create(null);
var _generation = 0;

// Drop every built client. The next login builds a new one from the current
// config, with empty discovery and JWKS caches. A login started before the
// reset fails at the callback, because its state records the old generation.
// A settings save resets the clients when it touches a Google or OIDC key, the
// origin or the port.
function reset() {
  _clients = Object.create(null);
  _generation += 1;
}
var CLIENT_KEY_RE = /^(google|oidc)|^(rpOrigin|port)$/;
config.onReset(function (changedKeys) {
  var keys = Array.isArray(changedKeys) ? changedKeys : [];
  if (keys.length === 0 || keys.some(function (k) { return CLIENT_KEY_RE.test(k); })) reset();
});

function _fail(reason) {
  var err = new Error("OpenID Connect sign-in failed: " + reason);
  err.oidcReason = reason;
  return err;
}

function isEnabled() {
  var o = config.oidc;
  return !!(o && o.enabled && o.issuer && o.clientID);
}

function _scopes(list) {
  var out = ["openid"];
  var items = Array.isArray(list) && list.length ? list : DEFAULT_SCOPES;
  for (var i = 0; i < items.length; i++) {
    if (items[i] && out.indexOf(items[i]) === -1) out.push(items[i]);
  }
  return out;
}

function _origin() {
  return config.rpOrigin || "http://localhost:" + (config.port || 3000); // allow:raw-time-literal — TCP port fallback, not duration
}

function callbackUrl(name) {
  if (name === "google") return config.google.callbackURL || _origin() + "/auth/google/callback";
  return config.oidc.callbackURL || _origin() + "/auth/oidc/callback";
}

function _isPlainHttpNonLoopback(url) {
  try {
    var u = b.safeUrl.parse(url, { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL });
    return u.protocol === "http:" && !b.ssrfGuard.isLoopbackHost(oidcPolicy.bareHost(u.hostname));
  } catch (_e) { return false; }
}

function _build(name) {
  if (name === "google") {
    if (!config.google.clientID) throw _fail("not-configured");
    var gopts = {
      provider: "google",
      clientId: config.google.clientID,
      redirectUri: callbackUrl("google"),
    };
    if (config.google.clientSecret) gopts.clientSecret = config.google.clientSecret;
    return b.auth.oauth.create(gopts);
  }
  if (name !== "oidc") throw _fail("unknown-provider");
  var o = config.oidc;
  if (!isEnabled()) throw _fail("not-configured");
  if (oidcPolicy.validateOidcConfig(o)) throw _fail("invalid-config");
  var cidrs = oidcPolicy.parseInternalCidrs(o.allowInternal).cidrs;
  var pol = oidcPolicy.issuerPolicy(o.issuer, cidrs);
  var redirectUri = callbackUrl("oidc");
  var allowHttp = pol.http || _isPlainHttpNonLoopback(redirectUri);
  var opts = {
    provider: "generic",
    isOidc: true,
    issuer: o.issuer,
    clientId: o.clientID,
    redirectUri: redirectUri,
    scope: _scopes(o.scopes),
    allowHttp: allowHttp,
  };
  if (o.clientSecret) opts.clientSecret = o.clientSecret;
  if (cidrs.length) opts.allowInternal = cidrs;
  // With plain http in play, every request is held to the issuer's own host.
  if (allowHttp) opts.http = { client: b.httpClient, allowedHosts: [pol.host] };
  return b.auth.oauth.create(opts);
}

/**
 * The client for `name` ("google" or "oidc"), built on first use after each
 * config reload. Returns { client, generation }.
 */
function getClient(name) {
  var entry = _clients[name];
  if (entry) return entry;
  var client;
  try { client = _build(name); }
  catch (e) { throw e && e.oidcReason ? e : _fail("client-setup"); }
  entry = { client: client, generation: _generation };
  _clients[name] = entry;
  return entry;
}

function _codeFailure(e, fallback) {
  if (e && e.oidcReason) return e;
  var code = e && typeof e.code === "string" && e.code.length <= MAX_ERROR_CODE_LENGTH && ERROR_CODE_RE.test(e.code) ? e.code : fallback;
  var err = _fail(code);
  if (e && typeof e.opError === "string") err.opError = e.opError.slice(0, MAX_OP_ERROR_LENGTH).replace(/[^A-Za-z0-9_\-.]/g, "");
  return err;
}

/**
 * Begin a login: write the pending state into the session and return the
 * authorization URL to redirect to.
 */
async function startLogin(name, req) {
  var key = STATE_KEYS[name];
  if (!key) throw _fail("unknown-provider");
  var entry = getClient(name);
  var a;
  try {
    a = await entry.client.authorizationUrl(name === "google" ? { prompt: "select_account" } : {});
  } catch (e) {
    throw _codeFailure(e, "authorization-url");
  }
  req.session[key] = {
    value: a.state,
    nonce: a.nonce,
    verifier: a.verifier,
    ts: Date.now(),
    gen: entry.generation,
  };
  return a.url;
}

var CALLBACK_KEYS = ["code", "state", "iss", "error", "error_description"];

function _callbackQuery(query) {
  var out = {};
  var q = query || {};
  for (var i = 0; i < CALLBACK_KEYS.length; i++) {
    var k = CALLBACK_KEYS[i];
    if (!Object.prototype.hasOwnProperty.call(q, k) || q[k] === undefined) continue;
    // A repeated parameter arrives as an array. No conforming provider sends
    // one, so it is refused rather than resolved to either value.
    if (typeof q[k] !== "string") throw _fail("bad-callback-parameter");
    out[k] = q[k];
  }
  return out;
}

/**
 * Verified email from a claim set: a valid address with the boolean
 * `email_verified: true`, lowercased. Anything else returns null.
 */
function verifiedEmail(src) {
  if (!src || typeof src !== "object" || src.email_verified !== true) return null;
  if (typeof src.email !== "string") return null;
  var e = src.email.trim().toLowerCase();
  if (!e || e.length > MAX_EMAIL_LENGTH) return null;
  var chk = b.guardEmail.validateAddress(e);
  if (!chk || !chk.ok) return null;
  return e;
}

function cleanDisplayName(name, email) {
  var n = typeof name === "string" ? name.replace(CONTROL_STRIP_RE, "").trim() : "";
  if (!n && email) n = String(email).split("@")[0];
  return n.slice(0, MAX_DISPLAY_NAME_LENGTH);
}

// Only an https URL of bounded length is stored as an avatar.
function cleanAvatar(url) {
  if (typeof url !== "string" || !url || url.length > MAX_AVATAR_LENGTH || CONTROL_TEST_RE.test(url)) return "";
  try {
    var u = b.safeUrl.parse(url, { allowedProtocols: b.safeUrl.ALLOW_HTTP_TLS });
    return u.protocol === "https:" ? url : "";
  } catch (_e) { return ""; }
}

/**
 * Read a groups claim. `path` is a claim name or a dotted path. Returns an
 * array of strings (at most 1000 entries of up to 256 characters each), or
 * null when the claim is absent. Matching against it is exact and
 * case-sensitive.
 */
function extractGroups(claims, path) {
  if (!claims || typeof claims !== "object") return null;
  var segs = String(path || "groups").split(".");
  var cur = claims;
  for (var i = 0; i < segs.length; i++) {
    if (oidcPolicy.FORBIDDEN_PATH_SEGMENTS[segs[i]]) return null;
    if (!cur || typeof cur !== "object" || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, segs[i])) return null;
    cur = cur[segs[i]];
  }
  if (cur === undefined || cur === null) return null;
  if (typeof cur === "string") return cur.length > 0 && cur.length <= MAX_GROUP_LENGTH ? [cur] : [];
  if (!Array.isArray(cur)) return [];
  var out = [];
  for (var j = 0; j < cur.length && out.length < MAX_GROUPS; j++) {
    if (typeof cur[j] === "string" && cur[j].length > 0 && cur[j].length <= MAX_GROUP_LENGTH) out.push(cur[j]);
  }
  return out;
}

/**
 * Finish a login from the callback request. The pending state is single-use:
 * it is removed from the session before anything else is checked. The
 * callback and the id_token are then verified, and the identity record
 * described at the top of this file is returned.
 *
 * opts.needGroups: read the groups claim, falling back to userinfo when the
 * id_token does not carry it.
 */
async function completeLogin(name, req, opts) {
  opts = opts || {};
  var key = STATE_KEYS[name];
  if (!key) throw _fail("unknown-provider");
  var st = req.session ? req.session[key] : null;
  if (req.session) delete req.session[key];
  if (!st || typeof st !== "object" || typeof st.value !== "string" || !st.value) throw _fail("state-missing");
  var age = Date.now() - Number(st.ts || 0);
  if (!(age >= 0 && age <= STATE_MAX_AGE_MS)) throw _fail("state-expired");

  var entry = getClient(name);
  if (st.gen !== entry.generation) throw _fail("config-changed");
  var client = entry.client;

  var tokens;
  try {
    var parsed = await client.parseCallback(_callbackQuery(req.query), { expectedState: st.value });
    tokens = await client.exchangeCode({ code: parsed.code, verifier: st.verifier, nonce: st.nonce });
  } catch (e) {
    throw _codeFailure(e, "callback");
  }
  // A token response without an id_token yields no claims. That is a failure,
  // never an unauthenticated success.
  if (!tokens || !tokens.claims || typeof tokens.claims !== "object") throw _fail("no-id-token");
  var claims = tokens.claims;
  if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > MAX_SUB_LENGTH || CONTROL_TEST_RE.test(claims.sub)) {
    throw _fail("bad-subject");
  }
  if (typeof claims.iss !== "string" || !claims.iss) throw _fail("bad-issuer");

  var email = verifiedEmail(claims);
  var groupsPath = name === "oidc" ? (config.oidc.groupsClaim || "groups") : "groups";
  var groups = opts.needGroups ? extractGroups(claims, groupsPath) : null;

  // userinfo is read at most once: when the id_token yields no verified email
  // (the claim is absent, or email_verified is missing or false), and when
  // groups are needed and the id_token has none. fetchUserInfo refuses a
  // response whose sub differs from the id_token's.
  var userinfo = null;
  if ((email === null || (opts.needGroups && groups === null)) && tokens.accessToken) {
    try { userinfo = await client.fetchUserInfo(tokens.accessToken, { idTokenSub: claims.sub }); }
    catch (_e) { userinfo = null; }
  }
  if (email === null && userinfo) email = verifiedEmail(userinfo);
  if (opts.needGroups && groups === null && userinfo) groups = extractGroups(userinfo, groupsPath);

  return {
    provider: name,
    issuer: claims.iss,
    sub: claims.sub,
    email: email,
    displayName: cleanDisplayName(claims.name || (userinfo && userinfo.name), email),
    avatar: cleanAvatar(claims.picture || (userinfo && userinfo.picture)),
    groups: groups,
  };
}

/**
 * Whether `url` may be sent as a plain-http redirect: only a URL on the
 * issuer's own host, when that issuer is reached over http inside an
 * OIDC_ALLOW_INTERNAL range.
 */
function isAllowedHttpRedirect(url) {
  var o = config.oidc;
  if (!isEnabled() || typeof url !== "string" || url.length > MAX_AUTH_URL_LENGTH || CONTROL_TEST_RE.test(url)) return false;
  var cidrs = oidcPolicy.parseInternalCidrs(o.allowInternal).cidrs;
  var pol = oidcPolicy.issuerPolicy(o.issuer, cidrs);
  if (pol.error || !pol.http) return false;
  try {
    var u = b.safeUrl.parse(url, { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL });
    return u.protocol === "http:" && oidcPolicy.bareHost(u.hostname) === pol.host;
  } catch (_e) { return false; }
}

/**
 * Send the browser to the provider's authorization URL. The router's
 * res.redirect only follows a fixed origin allowlist, and the generic
 * provider's origin comes from settings that change at runtime, so the 302 is
 * written here. The URL comes from the provider's discovery document (or
 * Google's), never from the request. It must be https, or http on the
 * issuer's own host as isAllowedHttpRedirect allows.
 */
function redirectToProvider(res, url) {
  var ok = false;
  if (typeof url === "string" && url.length <= MAX_AUTH_URL_LENGTH && !CONTROL_TEST_RE.test(url)) {
    try {
      ok = b.safeUrl.parse(url, { allowedProtocols: b.safeUrl.ALLOW_HTTP_TLS }).protocol === "https:";
    } catch (_e) { ok = false; }
    if (!ok) ok = isAllowedHttpRedirect(url);
  }
  if (!ok) throw _fail("unsafe-authorization-url");
  res.writeHead(302, { Location: url });
  res.end();
}

/**
 * A short reason string for the audit log. It never includes a token, a code
 * or a provider response body.
 */
function auditReason(err) {
  if (!err) return "unknown";
  var r = err.oidcReason || "callback failed";
  if (err.opError) r += " (" + err.opError + ")";
  return String(r).replace(CONTROL_STRIP_RE, "").slice(0, MAX_AUDIT_REASON_LENGTH);
}

module.exports = {
  getClient: getClient,
  reset: reset,
  isEnabled: isEnabled,
  callbackUrl: callbackUrl,
  startLogin: startLogin,
  completeLogin: completeLogin,
  verifiedEmail: verifiedEmail,
  extractGroups: extractGroups,
  cleanDisplayName: cleanDisplayName,
  cleanAvatar: cleanAvatar,
  auditReason: auditReason,
  isAllowedHttpRedirect: isAllowedHttpRedirect,
  redirectToProvider: redirectToProvider,
  STATE_KEYS: STATE_KEYS,
};
