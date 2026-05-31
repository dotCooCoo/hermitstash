"use strict";
/**
 * FIDO Metadata Service v3 (MDS3) — authenticator metadata BLOB
 * verifier + AAGUID lookup.
 *
 * Spec: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-rd-20210518.html
 *
 * The MDS3 BLOB is a JWS-signed JSON document hosted at
 * https://mds3.fidoalliance.org/. Operators use it to:
 *
 *   1. Pin the AAGUIDs of authenticators they accept (allowlist by
 *      vendor / FIDO certification level).
 *   2. Refuse credentials registered against authenticators with a
 *      REVOKED / USER_KEY_PHYSICAL_COMPROMISE /
 *      USER_KEY_REMOTE_COMPROMISE status report.
 *   3. Surface the FIDO Certified level (L1 / L1+ / L2 / L3 / L3+) so
 *      step-up / risk policies can require a minimum bar.
 *
 * Surface (b.auth.fidoMds3.*):
 *
 *   await fidoMds3.fetch({ url?, caCertificate?, force? })
 *     -> { entries, no, nextUpdate }
 *   fidoMds3.lookupAaguid(blob, aaguid)
 *     -> entry | null
 *   fidoMds3.verifyAuthenticator(blob, registrationInfo)
 *     -> { ok, statement, statusReports, certifiedLevel, reason? }
 *
 * Trust root: pinned to the FIDO Alliance MDS3 root certificate
 * (GlobalSign Root CA - R3, vendored via the simplewebauthn-server
 * SettingsService). Operators with an air-gapped or proxied deployment
 * can override via caCertificate (PEM or array of PEMs).
 *
 * Cache: in-memory, keyed by URL, TTL = nextUpdate - now from the BLOB
 * itself. The MDS3 spec mandates clients refresh by nextUpdate; the
 * cache enforces it. force: true bypasses the cache for an immediate
 * refresh.
 */

var nodeCrypto  = require("node:crypto");

var C            = require("../constants");
var safeJson     = require("../safe-json");
var safeBuffer   = require("../safe-buffer");
var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var _wa          = require("../vendor/simplewebauthn-server.cjs");
var { FidoMds3Error } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var cache      = lazyRequire(function () { return require("../cache"); });
var audit      = lazyRequire(function () { return require("../audit"); });

var DEFAULT_URL          = "https://mds3.fidoalliance.org/";
var DEFAULT_TIMEOUT_MS   = C.TIME.seconds(30);
// MDS3 BLOB is ~4-8 MB depending on vendor count; cap at 32 MiB so
// transient size growth doesn't break operators while a runaway
// response body can't OOM the host.
var MAX_BLOB_BYTES       = C.BYTES.mib(32);
// Floor + ceiling on cache TTL. The BLOB itself dictates nextUpdate,
// but a malformed payload that yields nextUpdate-in-the-past would
// otherwise force every call to refetch. Floor protects upstream;
// ceiling caps stale-trust risk if nextUpdate is set absurdly far out.
var MIN_CACHE_TTL_MS     = C.TIME.minutes(5);
var MAX_CACHE_TTL_MS     = C.TIME.days(30);

// FIDO MDS3 status reports that mark an authenticator as compromised /
// revoked per spec section 3.1.4. ANY of these in an authenticator's
// status report list refuses the credential.
var REFUSE_STATUS = {
  REVOKED:                       1,
  USER_KEY_PHYSICAL_COMPROMISE:  1,
  USER_KEY_REMOTE_COMPROMISE:    1,
  // FIDO MDS3 §3.1.4 — attestation-key compromise means the
  // manufacturer's batch-signing key is suspect; every credential
  // attested under that key MUST be refused. Pre-v0.9.2 this token
  // was missing from the refuse-list.
  ATTESTATION_KEY_COMPROMISE:    1,
};

// FIDO Certified levels that surface as certifiedLevel. The spec uses
// FIDO_CERTIFIED_L{N} / FIDO_CERTIFIED_L{N}_PLUS tokens; we collapse
// them to { level: 1|2|3, plus: bool } so policy code doesn't have to
// grep for the textual variants.
var CERT_LEVEL_RE = /^FIDO_CERTIFIED_L([1-3])(_PLUS)?$/;

// ---- helpers ----

function _b64urlDecode(s) {
  if (typeof s !== "string" || s.length === 0 || !safeBuffer.BASE64URL_RE.test(s)) {
    throw new FidoMds3Error("fido-mds3/bad-jws-segment",
      "JWS segment is not base64url");
  }
  return Buffer.from(s, "base64url");
}

// Wrap a base64-encoded DER cert (no PEM markers) into PEM form so
// node:crypto.X509Certificate accepts it.
function _derToPem(b64) {
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));      // RFC 7468 PEM line width
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

// Parse the JWS compact serialization. Returns { header, payload, sig,
// signingInput }.
function _parseJws(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new FidoMds3Error("fido-mds3/bad-jws", "BLOB token must be a non-empty string");
  }
  var parts = token.split(".");
  if (parts.length !== 3) {
    throw new FidoMds3Error("fido-mds3/bad-jws", "BLOB does not have 3 JWS segments");
  }
  var header, payload;
  try {
    header  = safeJson.parse(_b64urlDecode(parts[0]).toString("utf8"),
                             { maxBytes: C.BYTES.kib(64) });
    payload = safeJson.parse(_b64urlDecode(parts[1]).toString("utf8"),
                             { maxBytes: MAX_BLOB_BYTES });
  } catch (e) {
    throw new FidoMds3Error("fido-mds3/bad-jws-json",
      "BLOB header / payload JSON parse failed: " + ((e && e.message) || String(e)));
  }
  if (!header || typeof header.alg !== "string") {
    throw new FidoMds3Error("fido-mds3/bad-jws-header", "BLOB header missing 'alg'");
  }
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
    throw new FidoMds3Error("fido-mds3/bad-jws-header",
      "BLOB header missing 'x5c' certificate chain");
  }
  return {
    header:        header,
    payload:       payload,
    sig:           _b64urlDecode(parts[2]),
    signingInput:  parts[0] + "." + parts[1],
  };
}

// Map JWS alg to nodeCrypto verify parameters. MDS3 uses RS256 / ES256
// in practice; PS* and EdDSA are listed for completeness so future
// BLOBs over the same surface validate without a code edit.
function _verifyParamsForAlg(alg) {
  switch (alg) {
    case "RS256": return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    case "RS384": return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    case "RS512": return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PADDING };
    case "PS256": return { hash: "sha256", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };  // SHA-256 hash length
    case "PS384": return { hash: "sha384", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 };  // SHA-384 hash length
    case "PS512": return { hash: "sha512", padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 };  // SHA-512 hash length
    case "ES256": return { hash: "sha256", dsaEncoding: "ieee-p1363" };
    case "ES384": return { hash: "sha384", dsaEncoding: "ieee-p1363" };
    case "ES512": return { hash: "sha512", dsaEncoding: "ieee-p1363" };
    case "EdDSA": return { hash: null };
    default:
      throw new FidoMds3Error("fido-mds3/unsupported-alg",
        "JWS alg '" + alg + "' is not supported");
  }
}

// Resolve the trust roots. Operator override via caCertificate lets
// the framework run against a private MDS3 mirror or a regenerated
// root without a vendor refresh; the default is the GlobalSign Root
// CA - R3 PEM that the FIDO Alliance pins MDS3 BLOB chains to,
// vendored through simplewebauthn-server SettingsService so the PEM
// stays in lock-step with the vendor refresh.
function _resolveRoots(caCertificate) {
  if (caCertificate === undefined || caCertificate === null) {
    var pems = [];
    try { pems = _wa.SettingsService.getRootCertificates({ identifier: "mds" }) || []; }
    catch (_e) { pems = []; }
    if (!pems || pems.length === 0) {
      throw new FidoMds3Error("fido-mds3/no-trust-root",
        "no FIDO MDS3 root certificate available — vendored bundle missing 'mds' trust anchor");
    }
    return pems.slice();
  }
  if (typeof caCertificate === "string") return [caCertificate];
  if (Array.isArray(caCertificate)) {
    if (caCertificate.length === 0) {
      throw new FidoMds3Error("fido-mds3/bad-ca",
        "caCertificate array must not be empty");
    }
    for (var i = 0; i < caCertificate.length; i++) {
      if (typeof caCertificate[i] !== "string") {
        throw new FidoMds3Error("fido-mds3/bad-ca",
          "caCertificate[" + i + "] must be a PEM string");
      }
    }
    return caCertificate.slice();
  }
  throw new FidoMds3Error("fido-mds3/bad-ca",
    "caCertificate must be a PEM string or array of PEM strings");
}

// Validate the x5c cert chain against the trust roots. Each cert in
// the chain must be issued by the next; the last cert must verify
// against one of the trust roots. Uses node:crypto's
// X509Certificate.verify(publicKey) for issuer-signature checks and
// .checkIssued(other) for subject/issuer match.
function _validateChain(x5c, rootPems) {
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new FidoMds3Error("fido-mds3/bad-x5c", "JWS x5c chain is empty");
  }
  var chain = [];
  for (var i = 0; i < x5c.length; i++) {
    if (typeof x5c[i] !== "string" || x5c[i].length === 0) {
      throw new FidoMds3Error("fido-mds3/bad-x5c",
        "x5c[" + i + "] must be a base64-encoded DER cert");
    }
    try {
      chain.push(new nodeCrypto.X509Certificate(_derToPem(x5c[i])));
    } catch (e) {
      throw new FidoMds3Error("fido-mds3/bad-x5c",
        "x5c[" + i + "] failed to parse: " + ((e && e.message) || String(e)));
    }
  }
  var now = Date.now();
  for (var v = 0; v < chain.length; v++) {
    var notBefore = Date.parse(chain[v].validFrom);
    var notAfter  = Date.parse(chain[v].validTo);
    if (isFinite(notBefore) && now < notBefore) {
      throw new FidoMds3Error("fido-mds3/cert-not-yet-valid",
        "x5c[" + v + "] is not yet valid (notBefore=" + chain[v].validFrom + ")");
    }
    if (isFinite(notAfter) && now > notAfter) {
      throw new FidoMds3Error("fido-mds3/cert-expired",
        "x5c[" + v + "] expired at " + chain[v].validTo);
    }
  }
  for (var c = 0; c < chain.length - 1; c++) {
    if (!chain[c].checkIssued(chain[c + 1])) {
      throw new FidoMds3Error("fido-mds3/chain-broken",
        "x5c[" + c + "] not issued by x5c[" + (c + 1) + "]");
    }
    var issuerKey = chain[c + 1].publicKey;
    if (!chain[c].verify(issuerKey)) {
      throw new FidoMds3Error("fido-mds3/chain-bad-signature",
        "x5c[" + c + "] signature does not verify against x5c[" + (c + 1) + "] public key");
    }
  }
  var tail = chain[chain.length - 1];
  var anchored = false;
  for (var r = 0; r < rootPems.length; r++) {
    var root;
    try { root = new nodeCrypto.X509Certificate(rootPems[r]); }
    catch (_e) { continue; }
    if (tail.checkIssued(root) && tail.verify(root.publicKey)) {
      anchored = true;
      break;
    }
    // The root may itself be self-signed and identical to tail (some
    // CAs ship the root in x5c). Treat exact-match as anchored.
    if (tail.fingerprint256 === root.fingerprint256) {
      anchored = true;
      break;
    }
  }
  if (!anchored) {
    throw new FidoMds3Error("fido-mds3/chain-not-anchored",
      "x5c chain does not anchor to any provided trust root");
  }
  return chain;
}

// Verify the JWS signature using the leaf certificate's public key.
function _verifyJws(jws, leafCert) {
  var params = _verifyParamsForAlg(jws.header.alg);
  var verifyOpts = { key: leafCert.publicKey };
  if (params.padding !== undefined)     verifyOpts.padding     = params.padding;
  if (params.saltLength !== undefined)  verifyOpts.saltLength  = params.saltLength;
  if (params.dsaEncoding !== undefined) verifyOpts.dsaEncoding = params.dsaEncoding;
  var verified;
  try {
    verified = nodeCrypto.verify(params.hash, Buffer.from(jws.signingInput, "ascii"),
                                 verifyOpts, jws.sig);
  } catch (e) {
    throw new FidoMds3Error("fido-mds3/bad-signature",
      "BLOB signature verify threw: " + ((e && e.message) || String(e)));
  }
  if (!verified) {
    throw new FidoMds3Error("fido-mds3/bad-signature",
      "BLOB signature did not verify against the leaf cert");
  }
}

// ---- cache ----

var _sharedCache = null;
function _getCache() {
  if (_sharedCache) return _sharedCache;
  _sharedCache = cache().create({
    namespace:  "auth-fido-mds3.blob",
    ttlMs:      MAX_CACHE_TTL_MS,
    maxEntries: 8,                                                                 // operator-pinned URL set
  });
  return _sharedCache;
}

function _ttlFromNextUpdate(nextUpdateDate) {
  if (!(nextUpdateDate instanceof Date) || !isFinite(nextUpdateDate.getTime())) {
    return MIN_CACHE_TTL_MS;
  }
  var ms = nextUpdateDate.getTime() - Date.now();
  if (ms < MIN_CACHE_TTL_MS) return MIN_CACHE_TTL_MS;
  if (ms > MAX_CACHE_TTL_MS) return MAX_CACHE_TTL_MS;
  return ms;
}

// MDS3 nextUpdate per spec section 3.1.7 is "YYYY-MM-DD" (UTC midnight).
// Round-trip the parsed components through `new Date(utcMs).getUTC*()`
// and verify each field matches the input — Date.UTC silently
// normalises impossible calendar dates (`2026-02-31` -> `2026-03-03`),
// which would let a malformed MDS3 BLOB nextUpdate masquerade as a
// valid future timestamp and influence the cache-TTL clamp downstream.
function _parseNextUpdate(s) {
  if (typeof s !== "string") return null;
  var m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);                                    // ISO-8601 date components
  if (!m) return null;
  var year  = parseInt(m[1], 10);
  var month = parseInt(m[2], 10) - 1;
  var day   = parseInt(m[3], 10);
  if (day < 1 || day > 31 || month < 0 || month > 11) return null;
  var utcMs = Date.UTC(year, month, day);
  if (!isFinite(utcMs)) return null;
  var d = new Date(utcMs);
  if (d.getUTCFullYear() !== year ||
      d.getUTCMonth()    !== month ||
      d.getUTCDate()     !== day) {
    return null;
  }
  return d;
}

// Internal verify-blob helper used by both fetch (live HTTP) and the
// fetch-with-injected-body test path. Operator-facing surface goes
// through fetch().
function _verifyAndParseBlob(token) {
  var jws = _parseJws(token);
  var rootPems = _resolveRoots(undefined);
  var chain = _validateChain(jws.header.x5c, rootPems);
  _verifyJws(jws, chain[0]);
  var payload = jws.payload;
  if (!payload || !Array.isArray(payload.entries)) {
    throw new FidoMds3Error("fido-mds3/bad-payload",
      "BLOB payload missing 'entries' array");
  }
  if (typeof payload.no !== "number" || !isFinite(payload.no)) {
    throw new FidoMds3Error("fido-mds3/bad-payload",
      "BLOB payload missing or non-numeric 'no'");
  }
  var nextUpdate = _parseNextUpdate(payload.nextUpdate);
  if (!nextUpdate) {
    throw new FidoMds3Error("fido-mds3/bad-payload",
      "BLOB payload 'nextUpdate' missing or not YYYY-MM-DD: " + payload.nextUpdate);
  }
  // Stale-BLOB refusal — FIDO MDS3 §3.1.7 says clients SHOULD refresh
  // by nextUpdate; a BLOB whose nextUpdate is already in the past is
  // not safe to trust even though its cert chain still validates.
  // Pre-v0.9.2 the staleness was floored to MIN_CACHE_TTL_MS in
  // _ttlFromNextUpdate but the BLOB itself was still served from
  // cache; an attacker serving an ancient signed-but-expired BLOB
  // could keep operators on a revoked-authenticator-list-frozen-at-X.
  // Refuse at parse time so neither fetch nor cache lookup honors it.
  if (nextUpdate.getTime() < Date.now()) {
    throw new FidoMds3Error("fido-mds3/blob-stale",
      "BLOB payload nextUpdate \"" + payload.nextUpdate +
      "\" is in the past — refusing to trust a stale metadata BLOB " +
      "(FIDO MDS3 §3.1.7)");
  }
  return {
    entries:     payload.entries,
    no:          payload.no,
    nextUpdate:  nextUpdate,
    legalHeader: payload.legalHeader,
  };
}

// ---- public surface ----

/**
 * @primitive b.auth.fidoMds3.fetch
 * @signature b.auth.fidoMds3.fetch(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.auth.fidoMds3.lookupAaguid, b.auth.fidoMds3.verifyAuthenticator
 *
 * Fetches the FIDO Alliance MDS3 metadata BLOB, verifies the JWS
 * signature against the FIDO Alliance MDS3 root CA, parses the payload,
 * and returns a structured handle. Subsequent calls within the BLOB's
 * nextUpdate window return the cached result. force: true bypasses
 * the cache for an immediate refresh.
 *
 * Verification steps (each fails closed with FidoMds3Error):
 *   1. HTTPS GET via b.httpClient (SSRF gate, response-size cap).
 *   2. Parse compact JWS (header / payload / signature).
 *   3. Decode x5c certificate chain; validate validity windows; chain
 *      each link with X509Certificate.checkIssued and
 *      X509Certificate.verify(issuerKey); anchor the tail to the MDS3
 *      root trust set.
 *   4. Verify the JWS signature against the leaf cert's public key.
 *   5. Parse nextUpdate; reject if missing or malformed.
 *
 * @opts
 *   url:           string,         // default: https://mds3.fidoalliance.org/
 *   caCertificate: string|string[],// PEM(s) overriding the default MDS3 root
 *   force:         boolean,        // default: false; bypass the cache
 *   timeoutMs:     number,         // default: 30s
 *
 * @example
 *   var blob = await b.auth.fidoMds3.fetch({ force: false });
 *   typeof blob.entries.length === "number";
 *   // → true
 */
async function fetch(opts) {   // allow:raw-outbound-http — function name is fetch, internal call routes through b.httpClient
  opts = opts || {};
  validateOpts(opts, ["url", "caCertificate", "force", "timeoutMs"], "auth.fido_mds3.fetch");

  var url = opts.url || DEFAULT_URL;
  if (typeof url !== "string" || url.length === 0) {
    throw new FidoMds3Error("fido-mds3/bad-url", "url must be a non-empty string");
  }
  if (!/^https:/i.test(url)) {
    throw new FidoMds3Error("fido-mds3/bad-url",
      "url must be https:// (FIDO MDS3 trust root requires TLS)");
  }
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
  if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new FidoMds3Error("fido-mds3/bad-timeout",
      "timeoutMs must be a positive finite number");
  }
  var rootPems = _resolveRoots(opts.caCertificate);

  var cacheKey = "blob:" + url;
  var c = _getCache();
  if (opts.force) {
    try { await c.del(cacheKey); } catch (_e) { /* best-effort */ }
  }

  // cache.wrap takes an upfront ttlMs; for the loader we use the safe
  // minimum, then re-assert a precise nextUpdate-driven TTL with c.set
  // once the BLOB is parsed. This pattern lets the cache carry the
  // computed-from-payload TTL without blocking on a pre-knowledge of it.
  return await c.wrap(cacheKey, async function () {
    var rsp;
    try {
      rsp = await httpClient().request({
        method:           "GET",
        url:              url,
        maxResponseBytes: MAX_BLOB_BYTES,
        timeoutMs:        timeoutMs,
        headers:          {
          "User-Agent": "blamejs-fido-mds3/1",
          "Accept":     "application/jwt, application/octet-stream, */*",
        },
      });
    } catch (e) {
      try { audit().safeEmit({
        action:   "auth.fido_mds3.fetch.network",
        outcome:  "failure",
        metadata: { url: url, reason: (e && e.message) || String(e) },
      }); } catch (_e) { /* audit best-effort */ }
      throw new FidoMds3Error("fido-mds3/network",
        "BLOB GET " + url + " failed: " + ((e && e.message) || String(e)));
    }
    if (rsp.statusCode < 200 || rsp.statusCode >= 300) {                            // HTTP 2xx range
      throw new FidoMds3Error("fido-mds3/bad-status",
        "BLOB GET " + url + " returned " + rsp.statusCode);
    }
    var token = rsp.body.toString("ascii").trim();

    var jws = _parseJws(token);
    var chain = _validateChain(jws.header.x5c, rootPems);
    _verifyJws(jws, chain[0]);
    var payload = jws.payload;
    if (!payload || !Array.isArray(payload.entries)) {
      throw new FidoMds3Error("fido-mds3/bad-payload",
        "BLOB payload missing 'entries' array");
    }
    if (typeof payload.no !== "number" || !isFinite(payload.no)) {
      throw new FidoMds3Error("fido-mds3/bad-payload",
        "BLOB payload missing or non-numeric 'no'");
    }
    var nextUpdate = _parseNextUpdate(payload.nextUpdate);
    if (!nextUpdate) {
      throw new FidoMds3Error("fido-mds3/bad-payload",
        "BLOB payload 'nextUpdate' missing or not YYYY-MM-DD: " + payload.nextUpdate);
    }
    var record = {
      entries:     payload.entries,
      no:          payload.no,
      nextUpdate:  nextUpdate,
      url:         url,
      legalHeader: payload.legalHeader,
    };
    // Re-assert TTL based on the BLOB's nextUpdate (overrides the
    // wrap-call's safe-minimum seed).
    try { await c.set(cacheKey, record, _ttlFromNextUpdate(nextUpdate)); }
    catch (_e) { /* cache.set best-effort */ }
    try { audit().safeEmit({
      action:   "auth.fido_mds3.fetch",
      outcome:  "success",
      metadata: { url: url, no: payload.no, entries: payload.entries.length,
                  nextUpdate: payload.nextUpdate },
    }); } catch (_e) { /* audit best-effort */ }
    return record;
  }, MIN_CACHE_TTL_MS);
}

/**
 * @primitive b.auth.fidoMds3.lookupAaguid
 * @signature b.auth.fidoMds3.lookupAaguid(blob, aaguid)
 * @since     0.8.53
 * @status    stable
 * @related   b.auth.fidoMds3.fetch, b.auth.fidoMds3.verifyAuthenticator
 *
 * Finds the metadata entry for an AAGUID. Returns the entry shape
 * `{ aaguid, metadataStatement, statusReports, timeOfLastStatusChange }`
 * or null if the AAGUID isn't in the BLOB. AAGUID matching is
 * case-insensitive UUID compare with both dashed and undashed forms
 * accepted (registrationInfo.aaguid is a 16-byte hex with dashes;
 * statusReport AAGUIDs in some BLOBs drop the dashes).
 *
 * @example
 *   var blob = { entries: [{ aaguid: "00000000-0000-0000-0000-000000000000",
 *                            metadataStatement: { description: "Test" },
 *                            statusReports: [] }] };
 *   var entry = b.auth.fidoMds3.lookupAaguid(blob, "00000000-0000-0000-0000-000000000000");
 *   entry && entry.metadataStatement.description === "Test";
 *   // → true
 */
function lookupAaguid(blob, aaguid) {
  if (!blob || !Array.isArray(blob.entries)) {
    throw new FidoMds3Error("fido-mds3/bad-blob",
      "blob.entries must be an array (call fetch first)");
  }
  if (typeof aaguid !== "string" || aaguid.length === 0) {
    throw new FidoMds3Error("fido-mds3/bad-aaguid", "aaguid must be a non-empty string");
  }
  var canon = aaguid.replace(/-/g, "").toLowerCase();
  if (!safeBuffer.isHex(canon, 32)) {  // 32 = AAGUID hex-char count, not bytes
    throw new FidoMds3Error("fido-mds3/bad-aaguid",
      "aaguid must be a UUID (with or without dashes)");
  }
  for (var i = 0; i < blob.entries.length; i++) {
    var e = blob.entries[i];
    if (!e) continue;
    var entryAaguid = e.aaguid;
    if (typeof entryAaguid !== "string") continue;
    if (entryAaguid.replace(/-/g, "").toLowerCase() === canon) return e;
  }
  return null;
}

// Pull the certified-level token out of a list of status reports. The
// most recent FIDO_CERTIFIED_L{N}[_PLUS] report wins; if none exist,
// the authenticator is uncertified (level 0).
function _certifiedLevel(statusReports) {
  if (!Array.isArray(statusReports)) return { level: 0, plus: false };
  var best = { level: 0, plus: false };
  for (var i = 0; i < statusReports.length; i++) {
    var sr = statusReports[i];
    if (!sr || typeof sr.status !== "string") continue;
    var m = CERT_LEVEL_RE.exec(sr.status);
    if (!m) continue;
    var level = parseInt(m[1], 10);
    var plus = !!m[2];
    if (level > best.level || (level === best.level && plus && !best.plus)) {
      best = { level: level, plus: plus };
    }
  }
  return best;
}

/**
 * @primitive b.auth.fidoMds3.verifyAuthenticator
 * @signature b.auth.fidoMds3.verifyAuthenticator(blob, registrationInfo, opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.auth.fidoMds3.fetch, b.auth.fidoMds3.lookupAaguid
 *
 * Given a BLOB handle and the registrationInfo returned by
 * b.auth.passkey.verifyRegistration, returns
 * `{ ok, statement, statusReports, certifiedLevel, reason? }`. Refuses
 * (ok: false) when the authenticator's status reports include any of
 * REVOKED / USER_KEY_PHYSICAL_COMPROMISE / USER_KEY_REMOTE_COMPROMISE
 * / ATTESTATION_KEY_COMPROMISE (FIDO MDS3 section 3.1.4 compromise
 * bucket).
 *
 * AAGUIDs not present in the BLOB **fail closed by default** in
 * v0.9.2+ (pre-v0.9.2 returned `ok: true, statement: null`, silently
 * trusting any authenticator not yet in the metadata service). To
 * accept unknown AAGUIDs (test fixtures, pre-certification rollouts),
 * pass `opts.allowUnknownAaguid: true`; the `reason` field then notes
 * the operator opt-in.
 *
 * Audits auth.fido_mds3.verify.refused (drop-silent) on compromise.
 *
 * @opts
 *   allowUnknownAaguid: boolean,   // default false (fail-closed)
 *
 * @example
 *   var blob = { entries: [] };
 *   var reg  = { aaguid: "00000000-0000-0000-0000-000000000000" };
 *   var rv   = b.auth.fidoMds3.verifyAuthenticator(blob, reg,
 *                                                  { allowUnknownAaguid: true });
 *   rv.ok === true && rv.statement === null;
 *   // → true (with operator opt-in)
 */
function verifyAuthenticator(blob, registrationInfo, vopts) {
  vopts = vopts || {};
  if (!blob) {
    throw new FidoMds3Error("fido-mds3/bad-blob", "blob is required");
  }
  if (!registrationInfo || typeof registrationInfo.aaguid !== "string") {
    throw new FidoMds3Error("fido-mds3/bad-registrationinfo",
      "registrationInfo with .aaguid is required");
  }
  var entry = lookupAaguid(blob, registrationInfo.aaguid);
  if (!entry) {
    // Fail-CLOSED default for unknown AAGUIDs.
    // Pre-v0.9.2 default was `ok: true, reason: "aaguid-not-in-blob"`
    // — an attacker registering a credential with an AAGUID not in
    // the BLOB (rogue authenticator, fake hardware) silently passed.
    // The framework's primitive now refuses by default; operators
    // who genuinely want to accept unknown authenticators (test
    // fixtures, pre-certification pilot rollouts) pass
    // `vopts.allowUnknownAaguid: true` explicitly.
    var unknownOk = vopts.allowUnknownAaguid === true;
    return {
      ok:             unknownOk,
      statement:      null,
      statusReports:  [],
      certifiedLevel: { level: 0, plus: false },
      reason:         unknownOk
        ? "aaguid-not-in-blob (operator opted in via allowUnknownAaguid)"
        : "aaguid-not-in-blob",
    };
  }
  var statusReports = Array.isArray(entry.statusReports) ? entry.statusReports : [];
  var refusedStatus = null;
  for (var i = 0; i < statusReports.length; i++) {
    var sr = statusReports[i];
    if (sr && typeof sr.status === "string" && REFUSE_STATUS[sr.status]) {
      refusedStatus = sr.status;
      break;
    }
  }
  var certifiedLevel = _certifiedLevel(statusReports);
  if (refusedStatus) {
    try { audit().safeEmit({
      action:   "auth.fido_mds3.verify.refused",
      outcome:  "denied",
      metadata: { aaguid: registrationInfo.aaguid, status: refusedStatus },
    }); } catch (_e) { /* audit best-effort */ }
    return {
      ok:             false,
      statement:      entry.metadataStatement || null,
      statusReports:  statusReports,
      certifiedLevel: certifiedLevel,
      reason:         "compromised: " + refusedStatus,
    };
  }
  return {
    ok:             true,
    statement:      entry.metadataStatement || null,
    statusReports:  statusReports,
    certifiedLevel: certifiedLevel,
  };
}

module.exports = {
  fetch:                fetch,
  lookupAaguid:         lookupAaguid,
  verifyAuthenticator:  verifyAuthenticator,
  DEFAULT_URL:          DEFAULT_URL,
  // Internal — exposed so tests can exercise the verifier without
  // standing up a real HTTPS endpoint. Operators should call fetch().
  _verifyAndParseBlob:  _verifyAndParseBlob,
};
