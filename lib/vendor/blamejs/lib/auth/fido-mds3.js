// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto  = require("node:crypto");

var C            = require("../constants");
var safeJson     = require("../safe-json");
var safeBuffer   = require("../safe-buffer");
var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var x509Chain    = require("../x509-chain");
var jwtExternal  = require("./jwt-external");
var { FidoMds3Error } = require("../framework-error");

var httpClient = lazyRequire(function () { return require("../http-client"); });
var cache      = lazyRequire(function () { return require("../cache"); });
var audit      = lazyRequire(function () { return require("../audit"); });

var DEFAULT_URL          = "https://mds3.fidoalliance.org/";
var DEFAULT_TIMEOUT_MS   = C.TIME.seconds(30);
var MAX_BLOB_BYTES       = C.BYTES.mib(32);
var MIN_CACHE_TTL_MS     = C.TIME.minutes(5);
var MAX_CACHE_TTL_MS     = C.TIME.days(30);

var MDS3_ROOT_PEM = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G",
  "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp",
  "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4",
  "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG",
  "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI",
  "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8",
  "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT",
  "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm",
  "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd",
  "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ",
  "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw",
  "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o",
  "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU",
  "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp",
  "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK",
  "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX",
  "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs",
  "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH",
  "WD9f",
  "-----END CERTIFICATE-----",
  "",
].join("\n");

var REFUSE_STATUS = {
  REVOKED:                       1,
  USER_KEY_PHYSICAL_COMPROMISE:  1,
  USER_KEY_REMOTE_COMPROMISE:    1,
  ATTESTATION_KEY_COMPROMISE:    1,
};

var CERT_LEVEL_RE = /^FIDO_CERTIFIED_L([1-3])(_PLUS)?$/;

function _b64urlDecode(s) {
  if (!safeBuffer.isBase64Url(s)) {
    throw new FidoMds3Error("fido-mds3/bad-jws-segment",
      "JWS segment is not base64url");
  }
  return Buffer.from(s, "base64url");
}

function _derToPem(b64) {
  var lines = [];
  for (var i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return "-----BEGIN CERTIFICATE-----\n" + lines.join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

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

function _verifyParamsForAlg(alg) {
  var params = jwtExternal.algParams(alg);
  if (!params) {
    throw new FidoMds3Error("fido-mds3/unsupported-alg",
      "JWS alg '" + alg + "' is not supported");
  }
  return params;
}

function _resolveRoots(caCertificate) {
  if (caCertificate === undefined || caCertificate === null) {
    return [MDS3_ROOT_PEM];
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
    if (!isFinite(notBefore) || !isFinite(notAfter)) {
      throw new FidoMds3Error("fido-mds3/cert-bad-validity",
        "x5c[" + v + "] has unparseable validity dates (validFrom=" +
        chain[v].validFrom + ", validTo=" + chain[v].validTo + ")");
    }
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
    if (!x509Chain.issuerValidlyIssued(chain[c + 1], chain[c])) {
      throw new FidoMds3Error("fido-mds3/chain-broken",
        "x5c[" + c + "] not validly issued by x5c[" + (c + 1) +
        "] (issuer must be a CA whose signature over the subject verifies)");
    }
  }
  var tail = chain[chain.length - 1];
  var anchored = false;
  for (var r = 0; r < rootPems.length; r++) {
    var root;
    try { root = new nodeCrypto.X509Certificate(rootPems[r]); }
    catch (_e) { continue; }
    if (x509Chain.issuerValidlyIssued(root, tail)) {
      anchored = true;
      break;
    }
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

var _sharedCache = null;
function _getCache() {
  if (_sharedCache) return _sharedCache;
  _sharedCache = cache().create({
    namespace:  "auth-fido-mds3.blob",
    ttlMs:      MAX_CACHE_TTL_MS,
    maxEntries: 8,
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

function _parseNextUpdate(s) {
  if (typeof s !== "string") return null;
  var m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
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

function _verifyBlobWithRoots(token, rootPems) {
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
  if (nextUpdate.getTime() < Date.now()) {
    throw new FidoMds3Error("fido-mds3/blob-stale",
      "BLOB payload nextUpdate \"" + payload.nextUpdate +
      "\" is in the past -- refusing to trust a stale metadata BLOB " +
      "(FIDO MDS3 section 3.1.7)");
  }
  return {
    entries:     payload.entries,
    no:          payload.no,
    nextUpdate:  nextUpdate,
    legalHeader: payload.legalHeader,
  };
}

function _verifyAndParseBlob(token) {
  return _verifyBlobWithRoots(token, _resolveRoots(undefined));
}

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
 *   // requires: outbound HTTPS to the FIDO Metadata Service
 *   var blob = await b.auth.fidoMds3.fetch({ force: false });
 *   typeof blob.entries.length === "number";
 *   // → true
 */
async function fetch(opts) {   // allow:raw-outbound-http-framework-internal — function name is fetch, internal call routes through b.httpClient
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
    if (rsp.statusCode < 200 || rsp.statusCode >= 300) {
      throw new FidoMds3Error("fido-mds3/bad-status",
        "BLOB GET " + url + " returned " + rsp.statusCode);
    }
    var token = rsp.body.toString("ascii").trim();

    var record = _verifyBlobWithRoots(token, rootPems);
    record.url = url;
    try { await c.set(cacheKey, record, _ttlFromNextUpdate(record.nextUpdate)); }
    catch (_e) { /* cache.set best-effort */ }
    try { audit().safeEmit({
      action:   "auth.fido_mds3.fetch",
      outcome:  "success",
      metadata: { url: url, no: record.no, entries: record.entries.length,
                  nextUpdate: record.nextUpdate.toISOString().slice(0, 10) },
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
  if (!safeBuffer.isHex(canon, 32)) {
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

function _certifiedLevel(statusReports) {
  if (!Array.isArray(statusReports)) return { level: 0, plus: false };
  var latest = null;
  var latestDate = null;
  for (var i = 0; i < statusReports.length; i++) {
    var sr = statusReports[i];
    if (!sr || typeof sr.status !== "string" || sr.status.length > 64) continue;
    if (!CERT_LEVEL_RE.test(sr.status) && sr.status !== "NOT_FIDO_CERTIFIED") continue;
    var parsed = typeof sr.effectiveDate === "string" ? _parseNextUpdate(sr.effectiveDate) : null;
    var d = parsed ? parsed.getTime() : null;
    if (latest === null) { latest = sr; latestDate = d; continue; }
    if (d === null || latestDate === null || d >= latestDate) {
      latest = sr; latestDate = d;
    }
  }
  if (!latest || latest.status === "NOT_FIDO_CERTIFIED") return { level: 0, plus: false };
  var m = CERT_LEVEL_RE.exec(latest.status);
  return { level: parseInt(m[1], 10), plus: !!m[2] };
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
  _verifyAndParseBlob:  _verifyAndParseBlob,
  _defaultRootPems:     function () { return _resolveRoots(undefined); },
};
