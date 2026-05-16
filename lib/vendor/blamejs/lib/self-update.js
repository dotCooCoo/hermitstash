"use strict";
/**
 * @module b.selfUpdate
 * @nav    Production
 * @title  Self Update
 *
 * @intro
 *   Framework / vendored-deps integrity check plus version pinning —
 *   refuses to install a new build when the asset's detached signature
 *   does not verify against the operator-supplied public key, or when
 *   the vendored SHA the new build would ship does not match the
 *   manifest the operator pinned.
 *
 *   The lifecycle is four steps, each shippable as its own audit event:
 *
 *     1. `b.selfUpdate.poll({ releasesUrl, currentVersion })` fetches a
 *        releases feed (GitHub `/releases` shape or any feed exposing
 *        `{ tag_name, assets: [{ name, browser_download_url }] }`),
 *        compares semver-shaped tags, and reports whether a newer tag
 *        is available along with the matching asset and signature URLs.
 *     2. The operator downloads the asset bytes plus the detached
 *        signature via `b.httpClient.downloadStream` — the framework
 *        downloader handles SSRF guard, TLS posture, hash-while-
 *        streaming, and atomic rename of the temp file.
 *     3. `b.selfUpdate.verify({ assetPath, signaturePath, pubkeyPem })`
 *        verifies the detached signature over the asset bytes via
 *        `b.crypto.verify` (auto-detects ML-DSA-87 / Ed25519 / ECDSA
 *        P-384 from the supplied PEM) and reports the bytes' hash for
 *        SBOM correlation. A mismatched signature throws and the swap
 *        never runs.
 *     4. `b.selfUpdate.swap({ from, to, backupTo })` performs the
 *        atomic install: copy the current `to` to `backupTo`, rename
 *        `from` → `to`, fsync both directories. Cross-device renames
 *        fall back to copy + unlink. Any failure rolls back from the
 *        backup. `b.selfUpdate.rollback({ to, backupTo })` restores
 *        the backup post-swap when a healthcheck reports the new
 *        binary is bad.
 *
 *   Outbound HTTP routes through `b.httpClient.request` so SSRF,
 *   allowedHosts, and TLS posture defaults apply uniformly. Atomic file
 *   ops route through `b.atomicFile` (write + fsync + rename). Every
 *   step emits an audit event under `selfupdate.*` with `outcome:
 *   "denied"` on failure, so a tampered release surfaces in the audit
 *   log immediately even when the operator's own healthcheck missed it.
 *
 * @card
 *   Framework / vendored-deps integrity check plus version pinning — refuses to install a new build when the asset's detached signature does not verify against the operator-supplied public key, or when the vendored SHA the new build would ship does not match the manifest the opera...
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");
var nodeCrypto = require("node:crypto");
var numericBounds = require("./numeric-bounds");
var atomicFile = require("./atomic-file");
var validateOpts = require("./validate-opts");
var bCrypto = require("./crypto");
var httpClient = require("./http-client");
var safeJson = require("./safe-json");
var { URL: NodeUrl } = require("node:url");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var standaloneVerifier = require("./self-update-standalone-verifier");
var { boot } = require("./log");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var SelfUpdateError = defineClass("SelfUpdateError", { alwaysPermanent: true });
var log = boot("self-update");

// Algorithms accepted for the digest computed alongside verify. The
// signature itself is over the asset bytes; the digest is reported back
// to the operator for audit-trail / SBOM correlation.
var ALLOWED_HASH_ALGS = ["sha3-512", "sha-256", "sha-512", "shake256"];
var DEFAULT_HASH_ALG  = "sha3-512";
var DEFAULT_RELEASES_BYTES = C.BYTES.mib(8);     // GitHub releases JSON ~hundreds of KB; 8 MiB caps a malicious response

function _safeAuditEmit(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome || "success",
      metadata: metadata || {},
    });
  } catch (_e) { /* drop-silent — by design */ }
}

// ---- semver-shaped comparison (tag_name like "v0.7.30" or "0.7.30") ----
function _normalizeTag(tag) {
  if (typeof tag !== "string") return "";
  return tag.replace(/^v/i, "").trim();
}

/**
 * @primitive b.selfUpdate.compareTags
 * @signature b.selfUpdate.compareTags(a, b)
 * @since     0.9.47
 * @status    stable
 *
 * Compare two release tags / version strings. Returns `-1` if `a < b`,
 * `+1` if `a > b`, `0` if equal. Strips a leading `v` / `V`, then walks
 * dot-separated components: numeric pairs compared numerically; any
 * non-numeric component (release suffixes like `1.0.0-rc.1`) falls back
 * to lexicographic compare on that component. Missing components on
 * either side are treated as `"0"`.
 *
 * Shape follows SemVer 2.0.0 §11 precedence rules for the numeric prefix.
 * Deviations from the full SemVer §11 spec — pre-release identifiers
 * (`-rc.1` < release) are compared lexicographically rather than the
 * SemVer-mandated "alphanumeric identifiers compared as numbers if all
 * numeric" rule. For most version-shaped strings the result is identical;
 * exotic pre-release shapes (`1.0.0-alpha.10` vs `1.0.0-alpha.9`) sort
 * lexicographically here (`10` < `9` as strings) rather than numerically.
 * Operators with strict SemVer §11 needs should use a dedicated SemVer
 * parser; this primitive targets the common framework-update polling
 * shape (`v0.9.46` vs `v0.9.47`) where pre-release tags are rare.
 *
 * @example
 *   b.selfUpdate.compareTags("v0.9.46", "v0.9.47");   // → -1
 *   b.selfUpdate.compareTags("v0.9.47", "0.9.47");    // → 0  (leading "v" stripped)
 *   b.selfUpdate.compareTags("1.10.0",  "1.9.0");     // → +1 (numeric, not lex)
 *   b.selfUpdate.compareTags("v0.7.30", "v0.7.30");   // → 0
 */
function _compareTags(a, b) {
  var na = _normalizeTag(a);
  var nb2 = _normalizeTag(b);
  var pa = na.split(".");
  var pbb = nb2.split(".");
  var len = Math.max(pa.length, pbb.length);
  for (var i = 0; i < len; i++) {
    var ai = pa[i] !== undefined ? pa[i] : "0";
    var bi = pbb[i] !== undefined ? pbb[i] : "0";
    var an = parseInt(ai, 10);
    var bn = parseInt(bi, 10);
    if (isFinite(an) && isFinite(bn) && String(an) === ai && String(bn) === bi) {
      if (an < bn) return -1;
      if (an > bn) return 1;
      continue;
    }
    if (ai < bi) return -1;
    if (ai > bi) return 1;
  }
  return 0;
}

// ---- poll ----

function _validatePollOpts(opts) {
  validateOpts.requireObject(opts, "selfUpdate.poll", SelfUpdateError, "selfupdate/bad-opts");
  validateOpts.requireNonEmptyString(opts.releasesUrl,
    "selfUpdate.poll: opts.releasesUrl", SelfUpdateError, "selfupdate/bad-releases-url");
  // Scheme enforcement at config-time so the bug surfaces here, not
  // inside the request loop. Default policy: https only. Operators
  // wiring against an internal mirror can pass allowedProtocols
  // explicitly to opt in to http (e.g. a TLS-terminating proxy
  // upstream of the framework process). The full SSRF / hostname /
  // length policy still runs inside httpClient.request.
  var parsedProto;
  try { parsedProto = new NodeUrl(opts.releasesUrl).protocol; }
  catch (_e) {
    throw new SelfUpdateError("selfupdate/bad-releases-url",
      "selfUpdate.poll: opts.releasesUrl is not parseable as a URL");
  }
  var allowedProtocols = Array.isArray(opts.allowedProtocols) && opts.allowedProtocols.length > 0
    ? opts.allowedProtocols.slice() : ["https:"];
  if (allowedProtocols.indexOf(parsedProto) === -1) {
    throw new SelfUpdateError("selfupdate/bad-releases-url",
      "selfUpdate.poll: opts.releasesUrl protocol '" + parsedProto +
      "' not in allowedProtocols [" + allowedProtocols.join(", ") + "]");
  }
  validateOpts.requireNonEmptyString(opts.currentVersion,
    "selfUpdate.poll: opts.currentVersion", SelfUpdateError, "selfupdate/bad-current-version");
  if (opts.assetPattern !== undefined && !(opts.assetPattern instanceof RegExp) &&
      typeof opts.assetPattern !== "string") {
    throw new SelfUpdateError("selfupdate/bad-asset-pattern",
      "selfUpdate.poll: opts.assetPattern must be a RegExp or string when present");
  }
  if (opts.signaturePattern !== undefined && !(opts.signaturePattern instanceof RegExp) &&
      typeof opts.signaturePattern !== "string") {
    throw new SelfUpdateError("selfupdate/bad-sig-pattern",
      "selfUpdate.poll: opts.signaturePattern must be a RegExp or string when present");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes,
    "selfUpdate.poll: opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
  numericBounds.requirePositiveFiniteIntIfPresent(opts.timeoutMs,
    "selfUpdate.poll: opts.timeoutMs", SelfUpdateError, "selfupdate/bad-timeout");
}

function _matchAsset(name, pattern, fallback) {
  if (pattern instanceof RegExp) return pattern.test(name);
  if (typeof pattern === "string") return name.indexOf(pattern) !== -1;
  // Fallback heuristic — the caller didn't pass a pattern. Accept the
  // first asset whose name fits the well-known shape (tarball / zip /
  // .sig). The fallback is documented as best-effort; operators with
  // multi-asset releases should pass a pattern explicitly.
  return fallback ? fallback.test(name) : false;
}

/**
 * @primitive b.selfUpdate.poll
 * @signature b.selfUpdate.poll(opts)
 * @since     0.6.0
 * @related   b.selfUpdate.verify, b.selfUpdate.swap, b.httpClient.request
 *
 * Fetch a releases feed and report whether a newer tag is available.
 * Tags are compared semver-style with a leading `v` stripped. When
 * `opts.etag` is supplied an `If-None-Match` header makes a 304 a fast
 * "no update" path. The match against asset and signature URLs uses
 * `opts.assetPattern` and `opts.signaturePattern` (RegExp or substring)
 * with conservative fallbacks. Throws SelfUpdateError on a non-2xx
 * upstream, malformed JSON, or unexpected shape.
 *
 * @opts
 *   releasesUrl:      string,    // required — feed URL
 *   currentVersion:   string,    // required — e.g. "0.8.43" or "v0.8.43"
 *   assetPattern:     RegExp,    // match for the runtime asset (default well-known shapes)
 *   signaturePattern: RegExp,    // match for the detached signature (default .sig/.asc)
 *   allowedProtocols: array,     // default ["https:"]
 *   allowedHosts:     array,     // routed into httpClient SSRF gate
 *   allowInternal:    boolean,   // routed into httpClient SSRF gate
 *   maxBytes:         number,    // response cap (default 8 MiB)
 *   timeoutMs:        number,    // request timeout (default 15s)
 *   headers:          object,    // additional request headers
 *   etag:             string,    // last-seen etag for If-None-Match
 *
 * @example
 *   try {
 *     await b.selfUpdate.poll({
 *       releasesUrl:    "https://updates.invalid.localhost/releases.json",
 *       currentVersion: "0.8.43",
 *       timeoutMs:      1,
 *     });
 *   } catch (e) {
 *     e.code;                  // → "selfupdate/poll-failed"
 *   }
 */
async function poll(opts) {
  _validatePollOpts(opts);
  var maxBytes  = typeof opts.maxBytes  === "number" ? opts.maxBytes  : DEFAULT_RELEASES_BYTES;
  var timeoutMs = typeof opts.timeoutMs === "number" ? opts.timeoutMs : C.TIME.seconds(15);

  var headers = Object.assign({
    "Accept":     "application/json",
    "User-Agent": "blamejs-selfupdate/" + C.version,
  }, opts.headers || {});
  if (typeof opts.etag === "string" && opts.etag.length > 0) {
    headers["If-None-Match"] = opts.etag;
  }

  var res;
  try {
    res = await httpClient.request({
      method:           "GET",
      url:              opts.releasesUrl,
      headers:          headers,
      timeoutMs:        timeoutMs,
      maxResponseBytes: maxBytes,
      allowedHosts:     opts.allowedHosts,
      allowedProtocols: opts.allowedProtocols,
      allowInternal:    opts.allowInternal,
      errorClass:       SelfUpdateError,
    });
  } catch (e) {
    _safeAuditEmit("selfupdate.poll.checked", "denied", {
      releasesUrl: opts.releasesUrl, reason: "request-failed",
      message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/poll-failed",
      "selfUpdate.poll: request failed: " + ((e && e.message) || String(e)));
  }

  if (res.statusCode === 304) {                                                    // allow:raw-byte-literal — HTTP status code (RFC 7232), not bytes
    _safeAuditEmit("selfupdate.poll.checked", "success", {
      releasesUrl:    opts.releasesUrl,
      currentVersion: opts.currentVersion,
      available:      false,
      etagHit:        true,
    });
    return { available: false, latestTag: null, currentVersion: opts.currentVersion,
             asset: null, signature: null, etag: opts.etag, statusCode: 304 };    // allow:raw-byte-literal — HTTP status code (RFC 7232), not bytes
  }
  if (res.statusCode < 200 || res.statusCode >= 300) {
    _safeAuditEmit("selfupdate.poll.checked", "denied", {
      releasesUrl: opts.releasesUrl, reason: "non-2xx", statusCode: res.statusCode,
    });
    throw new SelfUpdateError("selfupdate/poll-non-2xx",
      "selfUpdate.poll: upstream returned HTTP " + res.statusCode);
  }

  var bodyBuf = Buffer.isBuffer(res.body) ? res.body :
    (res.body == null ? Buffer.alloc(0) : Buffer.from(String(res.body), "utf8"));
  var parsed;
  try {
    parsed = safeJson.parse(bodyBuf, { maxBytes: maxBytes });
  } catch (e) {
    _safeAuditEmit("selfupdate.poll.checked", "denied", {
      releasesUrl: opts.releasesUrl, reason: "bad-json",
      message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/bad-json",
      "selfUpdate.poll: response is not valid JSON: " + ((e && e.message) || String(e)));
  }

  // Normalize: GitHub /releases/latest returns one object, /releases
  // returns an array. Either is accepted; the array path picks the
  // first entry sorted by tag_name descending so prerelease ordering
  // matches semver-ish.
  var latest;
  if (Array.isArray(parsed)) {
    if (parsed.length === 0) {
      _safeAuditEmit("selfupdate.poll.checked", "success", {
        releasesUrl: opts.releasesUrl, currentVersion: opts.currentVersion,
        available: false, reason: "empty-feed",
      });
      return { available: false, latestTag: null, currentVersion: opts.currentVersion,
               asset: null, signature: null };
    }
    var sorted = parsed.slice().sort(function (a, b) {
      return _compareTags(b && b.tag_name, a && a.tag_name);
    });
    latest = sorted[0];
  } else if (parsed && typeof parsed === "object") {
    latest = parsed;
  } else {
    throw new SelfUpdateError("selfupdate/bad-shape",
      "selfUpdate.poll: response shape must be { tag_name, assets[] } or array of same");
  }

  if (!latest || typeof latest.tag_name !== "string") {
    throw new SelfUpdateError("selfupdate/bad-shape",
      "selfUpdate.poll: latest release missing tag_name");
  }

  var available = _compareTags(latest.tag_name, opts.currentVersion) > 0;
  if (!available) {
    _safeAuditEmit("selfupdate.poll.checked", "success", {
      releasesUrl:    opts.releasesUrl,
      currentVersion: opts.currentVersion,
      latestTag:      latest.tag_name,
      available:      false,
    });
    return { available: false, latestTag: latest.tag_name,
             currentVersion: opts.currentVersion, asset: null, signature: null,
             etag: (res.headers && (res.headers.etag || res.headers.ETag)) || null };
  }

  var assets = Array.isArray(latest.assets) ? latest.assets : [];
  var assetMatch     = null;
  var signatureMatch = null;
  for (var i = 0; i < assets.length; i++) {
    var a = assets[i] || {};
    if (typeof a.name !== "string" || typeof a.browser_download_url !== "string") continue;
    if (signatureMatch === null && _matchAsset(a.name, opts.signaturePattern, /\.sig$|\.asc$|\.sig\.bin$/i)) {
      signatureMatch = { name: a.name, url: a.browser_download_url, size: a.size || null };
      continue;
    }
    if (assetMatch === null && _matchAsset(a.name, opts.assetPattern, /\.(tar\.gz|tgz|zip|node|exe|bin)$/i)) {
      assetMatch = { name: a.name, url: a.browser_download_url, size: a.size || null };
    }
  }

  _safeAuditEmit("selfupdate.poll.checked", "success", {
    releasesUrl:    opts.releasesUrl,
    currentVersion: opts.currentVersion,
    latestTag:      latest.tag_name,
    available:      true,
    asset:          assetMatch ? assetMatch.name : null,
    signature:      signatureMatch ? signatureMatch.name : null,
  });

  return {
    available:      true,
    latestTag:      latest.tag_name,
    currentVersion: opts.currentVersion,
    asset:          assetMatch,
    signature:      signatureMatch,
    etag:           (res.headers && (res.headers.etag || res.headers.ETag)) || null,
  };
}

// ---- verify ----

function _validateVerifyOpts(opts) {
  validateOpts.requireObject(opts, "selfUpdate.verify", SelfUpdateError, "selfupdate/bad-opts");
  validateOpts.requireNonEmptyString(opts.assetPath,
    "selfUpdate.verify: opts.assetPath", SelfUpdateError, "selfupdate/bad-asset-path");
  validateOpts.requireNonEmptyString(opts.signaturePath,
    "selfUpdate.verify: opts.signaturePath", SelfUpdateError, "selfupdate/bad-signature-path");
  validateOpts.requireNonEmptyString(opts.pubkeyPem,
    "selfUpdate.verify: opts.pubkeyPem (PEM-encoded public key)",
    SelfUpdateError, "selfupdate/bad-pubkey");
  if (opts.hashAlgo !== undefined &&
      (typeof opts.hashAlgo !== "string" || ALLOWED_HASH_ALGS.indexOf(opts.hashAlgo) === -1)) {
    throw new SelfUpdateError("selfupdate/bad-hash-algo",
      "selfUpdate.verify: opts.hashAlgo must be one of " + ALLOWED_HASH_ALGS.join(", "));
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes,
    "selfUpdate.verify: opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
}

/**
 * @primitive b.selfUpdate.verify
 * @signature b.selfUpdate.verify(opts)
 * @since     0.6.0
 * @related   b.selfUpdate.poll, b.selfUpdate.swap, b.crypto.verify
 *
 * Verify a detached signature over the asset bytes. The algorithm is
 * auto-detected from `opts.pubkeyPem` (ML-DSA-87 / Ed25519 / ECDSA
 * P-384) by `b.crypto.verify`. Reports the asset's hash alongside the
 * verified flag for SBOM / audit correlation; the supported digest
 * algorithms are sha3-512 (default), sha-256, sha-512, and shake256.
 * Throws SelfUpdateError on a missing file, a verify-time exception,
 * or a signature that does not verify.
 *
 * @opts
 *   assetPath:     string,   // required — path to the downloaded asset
 *   signaturePath: string,   // required — path to the detached signature
 *   pubkeyPem:     string,   // required — PEM-encoded public key
 *   hashAlgo:      string,   // sha3-512 | sha-256 | sha-512 | shake256 (default sha3-512)
 *   maxBytes:      number,   // asset read cap (default 1 GiB)
 *
 * @example
 *   try {
 *     await b.selfUpdate.verify({
 *       assetPath:     "/tmp/blamejs-doc-asset-not-present.tar.gz",
 *       signaturePath: "/tmp/blamejs-doc-asset-not-present.sig",
 *       pubkeyPem:     "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n",
 *     });
 *   } catch (e) {
 *     e.code;                 // → "selfupdate/read-failed"
 *   }
 */
async function verify(opts) {
  _validateVerifyOpts(opts);
  var alg = opts.hashAlgo || DEFAULT_HASH_ALG;

  var assetBytes;
  var sigBytes;
  try {
    assetBytes = await atomicFile.read(opts.assetPath, {
      maxBytes: typeof opts.maxBytes === "number" ? opts.maxBytes : C.BYTES.gib(1),
    });
    sigBytes = await atomicFile.read(opts.signaturePath, {
      maxBytes: C.BYTES.kib(64),
    });
  } catch (e) {
    _safeAuditEmit("selfupdate.verify.failed", "denied", {
      assetPath: opts.assetPath, signaturePath: opts.signaturePath,
      reason: "read-failed", message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/read-failed",
      "selfUpdate.verify: read failed: " + ((e && e.message) || String(e)));
  }

  var ok = false;
  try { ok = bCrypto.verify(assetBytes, sigBytes, opts.pubkeyPem); }
  catch (e) {
    _safeAuditEmit("selfupdate.verify.failed", "denied", {
      assetPath: opts.assetPath, signaturePath: opts.signaturePath,
      reason: "verify-threw", message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/verify-failed",
      "selfUpdate.verify: signature verify threw: " + ((e && e.message) || String(e)));
  }

  var hashHex = nodeCrypto.createHash(alg).update(assetBytes).digest("hex");

  if (!ok) {
    _safeAuditEmit("selfupdate.verify.failed", "denied", {
      assetPath: opts.assetPath, signaturePath: opts.signaturePath,
      alg: alg, hash: hashHex, reason: "signature-mismatch",
    });
    throw new SelfUpdateError("selfupdate/signature-mismatch",
      "selfUpdate.verify: signature did not verify against the supplied public key");
  }

  _safeAuditEmit("selfupdate.verify.passed", "success", {
    assetPath: opts.assetPath, signaturePath: opts.signaturePath,
    alg: alg, hash: hashHex, bytes: assetBytes.length,
  });
  log("selfUpdate.verify passed asset=" + opts.assetPath + " alg=" + alg);
  return { verified: true, hash: hashHex, alg: alg, bytes: assetBytes.length };
}

// ---- swap ----

function _validateSwapOpts(opts, label) {
  validateOpts.requireObject(opts, "selfUpdate." + label, SelfUpdateError, "selfupdate/bad-opts");
  if (label === "swap") {
    validateOpts.requireNonEmptyString(opts.from,
      "selfUpdate.swap: opts.from", SelfUpdateError, "selfupdate/bad-from");
  }
  validateOpts.requireNonEmptyString(opts.to,
    "selfUpdate." + label + ": opts.to", SelfUpdateError, "selfupdate/bad-to");
  validateOpts.requireNonEmptyString(opts.backupTo,
    "selfUpdate." + label + ": opts.backupTo", SelfUpdateError, "selfupdate/bad-backup");
}

// Atomic swap of `from` -> `to` with rollback on failure. Steps:
//
//   1. ensure `to` and `backupTo` parents exist
//   2. if `to` exists — copy bytes to `backupTo` (atomic write of the
//      backup, preserving the original on `to` until step 3)
//   3. rename `from` -> `to` (atomic on the same FS; cross-device is
//      detected and surfaced as selfupdate/cross-device)
//   4. fsync both directories (best-effort across platforms)
//
// If step 3 fails the backup remains; if step 4 fails the swap is
// considered complete (operator can audit) but a warning is logged.
/**
 * @primitive b.selfUpdate.swap
 * @signature b.selfUpdate.swap(opts)
 * @since     0.6.0
 * @related   b.selfUpdate.verify, b.selfUpdate.rollback, b.atomicFile.copy
 *
 * Atomic install: copy the existing `to` to `backupTo`, rename `from`
 * → `to`, then fsync both directories. Cross-device renames fall back
 * to copy + unlink on the destination filesystem. On any failure the
 * original `to` is restored from `backupTo`. Throws SelfUpdateError on
 * a missing `from`, backup-copy failure, cross-device install failure,
 * or rename failure.
 *
 * @opts
 *   from:     string,   // required — newly-installed asset path
 *   to:       string,   // required — target install path
 *   backupTo: string,   // required — backup path for the existing `to`
 *
 * @example
 *   try {
 *     await b.selfUpdate.swap({
 *       from:     "/tmp/blamejs-doc-missing.bin",
 *       to:       "/tmp/blamejs-doc-target.bin",
 *       backupTo: "/tmp/blamejs-doc-backup.bin",
 *     });
 *   } catch (e) {
 *     e.code;                 // → "selfupdate/missing-from"
 *   }
 */
async function swap(opts) {
  _validateSwapOpts(opts, "swap");
  var from     = opts.from;
  var to       = opts.to;
  var backupTo = opts.backupTo;

  if (!nodeFs.existsSync(from)) {
    throw new SelfUpdateError("selfupdate/missing-from",
      "selfUpdate.swap: from path does not exist: " + from);
  }

  var toDir       = nodePath.dirname(to);
  var backupDir   = nodePath.dirname(backupTo);
  atomicFile.ensureDir(toDir);
  atomicFile.ensureDir(backupDir);

  // Step 2 — backup if `to` exists. Use atomicFile.copy so the backup
  // hits disk via temp+fsync+rename.
  var hadOriginal = nodeFs.existsSync(to);
  if (hadOriginal) {
    try {
      await atomicFile.copy(to, backupTo, { fileMode: 0o600 });
    } catch (e) {
      throw new SelfUpdateError("selfupdate/backup-failed",
        "selfUpdate.swap: failed to copy " + to + " -> " + backupTo + ": " +
        ((e && e.message) || String(e)));
    }
  }

  // Step 3 — install. Rename is atomic on same FS; on cross-device we
  // fall back to copy + unlink.
  try {
    nodeFs.renameSync(from, to);
  } catch (e) {
    if (e && e.code === "EXDEV") {
      // Cross-device — copy + unlink. Use atomicFile.copy for the safety
      // net (temp+fsync+rename on dest FS); then remove the source.
      try {
        await atomicFile.copy(from, to, { fileMode: 0o600 });
        try { nodeFs.unlinkSync(from); } catch (_u) { /* tmp source leak — operator-cleanable */ }
      } catch (ce) {
        // Roll back from backup if we have one.
        if (hadOriginal) {
          try { await atomicFile.copy(backupTo, to, { fileMode: 0o600 }); }
          catch (_re) { /* rollback best-effort — operator surfaces via audit */ }
        }
        throw new SelfUpdateError("selfupdate/cross-device",
          "selfUpdate.swap: cross-device install failed: " + ((ce && ce.message) || String(ce)));
      }
    } else {
      // Other rename failure — try to roll back.
      if (hadOriginal) {
        try { await atomicFile.copy(backupTo, to, { fileMode: 0o600 }); }
        catch (_re) { /* rollback best-effort */ }
      }
      throw new SelfUpdateError("selfupdate/swap-failed",
        "selfUpdate.swap: rename " + from + " -> " + to + " failed: " + e.message);
    }
  }

  // Step 4 — fsync directories so the rename is durable.
  atomicFile.fsyncDir(toDir);
  if (backupDir !== toDir) atomicFile.fsyncDir(backupDir);

  var swappedAt = Date.now();
  _safeAuditEmit("selfupdate.swap.completed", "success", {
    from: from, to: to, backupTo: backupTo, hadOriginal: hadOriginal,
  });
  log("selfUpdate.swap completed from=" + from + " to=" + to);
  return { ok: true, swappedAt: swappedAt, from: from, to: to, backupTo: backupTo };
}

// ---- rollback ----

/**
 * @primitive b.selfUpdate.rollback
 * @signature b.selfUpdate.rollback(opts)
 * @since     0.6.0
 * @related   b.selfUpdate.swap, b.atomicFile.copy
 *
 * Restore `backupTo` → `to` via the same atomic copy used by `swap`.
 * Operators run rollback when a post-swap healthcheck reports the new
 * binary is bad. Throws SelfUpdateError when the backup file is
 * missing or the copy fails.
 *
 * @opts
 *   to:       string,   // required — target path to restore
 *   backupTo: string,   // required — source backup path
 *
 * @example
 *   try {
 *     await b.selfUpdate.rollback({
 *       to:       "/tmp/blamejs-doc-target.bin",
 *       backupTo: "/tmp/blamejs-doc-missing-backup.bin",
 *     });
 *   } catch (e) {
 *     e.code;                 // → "selfupdate/missing-backup"
 *   }
 */
async function rollback(opts) {
  _validateSwapOpts(opts, "rollback");
  var to       = opts.to;
  var backupTo = opts.backupTo;

  if (!nodeFs.existsSync(backupTo)) {
    throw new SelfUpdateError("selfupdate/missing-backup",
      "selfUpdate.rollback: backupTo path does not exist: " + backupTo);
  }

  atomicFile.ensureDir(nodePath.dirname(to));
  try {
    await atomicFile.copy(backupTo, to, { fileMode: 0o600 });
  } catch (e) {
    throw new SelfUpdateError("selfupdate/rollback-failed",
      "selfUpdate.rollback: copy " + backupTo + " -> " + to + " failed: " +
      ((e && e.message) || String(e)));
  }
  atomicFile.fsyncDir(nodePath.dirname(to));

  _safeAuditEmit("selfupdate.rollback.completed", "success", {
    to: to, backupTo: backupTo,
  });
  log("selfUpdate.rollback restored " + to + " from " + backupTo);
  return { ok: true, restoredAt: Date.now(), to: to, backupTo: backupTo };
}

module.exports = {
  poll:                  poll,
  verify:                verify,
  swap:                  swap,
  rollback:              rollback,
  // Standalone verifier — zero-dep companion for install-pipeline
  // contexts that run BEFORE the framework is installed (Dockerfile
  // build stages, install.sh, update.sh). See the module's intro for
  // the copy-this-file workflow.
  standaloneVerifier:    standaloneVerifier,
  SelfUpdateError:       SelfUpdateError,
  ALLOWED_HASH_ALGS:     ALLOWED_HASH_ALGS,
  DEFAULT_HASH_ALG:      DEFAULT_HASH_ALG,
  // Public surface — same impl as the internal `_compareTags`;
  // downstream consumers replacing one-off compareVersions helpers
  // call this.
  compareTags:           _compareTags,
  // Internal — exposed for the layer-0 test suite only.
  _compareTags:          _compareTags,
};
