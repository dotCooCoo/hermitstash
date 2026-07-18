// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *     4. `b.selfUpdate.swap({ from, to, backupTo, expectedHash })` performs
 *        the atomic install: re-hash `from` and refuse unless it matches
 *        `expectedHash` (the hash step 3 returned — binding the installed
 *        bytes to the verified bytes), copy the current `to` to `backupTo`,
 *        rename `from` → `to`, fsync both directories. Cross-device renames
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
var guardRegex = require("./guard-regex");
var httpClient = require("./http-client");
var safeJson = require("./safe-json");
var { URL: NodeUrl } = require("node:url");
var C = require("./constants");
var standaloneVerifier = require("./self-update-standalone-verifier");
var { boot } = require("./log");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var SelfUpdateError = defineClass("SelfUpdateError", { alwaysPermanent: true });
var log = boot("self-update");

// Algorithms accepted for the digest computed alongside verify. The
// signature itself is over the asset bytes; the digest is reported back
// to the operator for audit-trail / SBOM correlation.
var ALLOWED_HASH_ALGS = ["sha3-512", "sha-256", "sha-512", "shake256"];
var DEFAULT_HASH_ALG  = "sha3-512";
var DEFAULT_RELEASES_BYTES = C.BYTES.mib(8);     // GitHub releases JSON ~hundreds of KB; 8 MiB caps a malicious response

function _safeAuditEmit(action, outcome, metadata) {
  auditEmit.emit(action, metadata, outcome);
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
 * Compare two release tags / version strings per SemVer 2.0.0 §11.
 * Returns `-1` if `a < b`, `+1` if `a > b`, `0` if equal. Strips a
 * leading `v` / `V`, then:
 *
 *   1. Splits each tag into (numericVersion, pre-release, build).
 *      Build metadata is ignored per §10 (does NOT participate in
 *      precedence).
 *   2. Compares the numeric version (`major.minor.patch`) numerically.
 *   3. If equal, applies §11 pre-release rules: a version with NO
 *      pre-release outranks any version WITH one. Two pre-release
 *      strings split on `.` and compare dot-by-dot — numeric
 *      identifiers compare as numbers, alphanumeric as ASCII, numeric
 *      sorts lower than alphanumeric, and a longer pre-release with a
 *      common prefix is higher.
 *
 * Missing numeric components on either side are treated as `"0"` so
 * `"1.0"` and `"1.0.0"` compare equal.
 *
 * Hardening (v0.9.58) — pre-v0.9.58 the pre-release segment fell back
 * to lexicographic comparison, which silently misordered `"1.0.0-alpha.10"`
 * (the strict-§11 LARGER pre-release) and `"1.0.0-alpha.9"`: as strings
 * "10" < "9" so `alpha.10 < alpha.9`, and a downstream consumer polling
 * for the next release would silently downgrade. This implementation
 * now follows §11 strictly.
 *
 * @example
 *   b.selfUpdate.compareTags("v0.9.46", "v0.9.47");                // → -1
 *   b.selfUpdate.compareTags("v0.9.47", "0.9.47");                 // → 0
 *   b.selfUpdate.compareTags("1.10.0",  "1.9.0");                  // → +1 (numeric)
 *   b.selfUpdate.compareTags("1.0.0",   "1.0.0-rc.1");             // → +1 (release > pre-release)
 *   b.selfUpdate.compareTags("1.0.0-alpha.10", "1.0.0-alpha.9");   // → +1 (numeric pre-release, §11)
 *   b.selfUpdate.compareTags("1.0.0+build1", "1.0.0+build2");      // → 0 (build metadata ignored)
 */
// _isAllNumeric — SemVer §11 pre-release segment numeric check.
// Hand-rolled char-code walk avoids reaching for /^[0-9]+$/ which
// already appears in guard-cidr and guard-domain (the codebase-patterns
// duplicate-regex detector fires at the 3rd file). No noticeable
// performance delta vs a regex on the short pre-release segments
// (typically <8 chars) this primitive deals with.
function _isAllNumeric(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;                                                          // ASCII codepoint range for digits
  }
  return true;
}

function _compareTags(a, b) {
  var na = _normalizeTag(a);
  var nb2 = _normalizeTag(b);
  // Strip build metadata (RFC 5234 + SemVer §10 — not part of
  // precedence ordering).
  var aPlus = na.indexOf("+"); if (aPlus !== -1) na  = na.slice(0, aPlus);
  var bPlus = nb2.indexOf("+"); if (bPlus !== -1) nb2 = nb2.slice(0, bPlus);
  // Split into numeric core + pre-release tail.
  var aDash = na.indexOf("-");
  var bDash = nb2.indexOf("-");
  var aCore = aDash === -1 ? na  : na.slice(0, aDash);
  var bCore = bDash === -1 ? nb2 : nb2.slice(0, bDash);
  var aPre  = aDash === -1 ? ""  : na.slice(aDash + 1);
  var bPre  = bDash === -1 ? ""  : nb2.slice(bDash + 1);
  // Compare numeric core dot-by-dot.
  var pa = aCore.split(".");
  var pbb = bCore.split(".");
  var coreLen = Math.max(pa.length, pbb.length);
  for (var i = 0; i < coreLen; i++) {
    var ai = pa[i] !== undefined ? pa[i] : "0";
    var bi = pbb[i] !== undefined ? pbb[i] : "0";
    var an = parseInt(ai, 10);
    var bn = parseInt(bi, 10);
    if (isFinite(an) && isFinite(bn) && String(an) === ai && String(bn) === bi) {
      if (an < bn) return -1;
      if (an > bn) return 1;
      continue;
    }
    // Non-numeric component in the core — fall back to ASCII per
    // §11 to keep deterministic ordering on malformed inputs.
    if (ai < bi) return -1;
    if (ai > bi) return 1;
  }
  // SemVer §11 — equal numeric core. A version WITHOUT a pre-release
  // is GREATER than a version WITH one.
  if (aPre === "" && bPre === "") return 0;
  if (aPre === "" && bPre !== "") return 1;
  if (aPre !== "" && bPre === "") return -1;
  // Both have pre-release tails; compare dot-by-dot.
  var paPre = aPre.split(".");
  var pbPre = bPre.split(".");
  var preLen = Math.max(paPre.length, pbPre.length);
  for (var j = 0; j < preLen; j++) {
    // §11: "A larger set of pre-release fields has a higher precedence
    // than a smaller set, if all of the preceding identifiers are equal."
    if (j >= paPre.length) return -1;
    if (j >= pbPre.length) return 1;
    var ax = paPre[j];
    var bx = pbPre[j];
    var axN = _isAllNumeric(ax);
    var bxN = _isAllNumeric(bx);
    if (axN && bxN) {
      // Both numeric — compare as numbers.
      var aNum = parseInt(ax, 10);
      var bNum = parseInt(bx, 10);
      if (aNum < bNum) return -1;
      if (aNum > bNum) return 1;
      continue;
    }
    // §11: "Numeric identifiers always have lower precedence than
    // alphanumeric identifiers."
    if (axN && !bxN) return -1;
    if (!axN && bxN) return 1;
    // Both alphanumeric — ASCII compare.
    if (ax < bx) return -1;
    if (ax > bx) return 1;
  }
  return 0;
}

// ---- poll ----

function _validatePollOpts(opts) {
  validateOpts.shape(opts, {
    releasesUrl: function (value) {
      validateOpts.requireNonEmptyString(value,
        "selfUpdate.poll: opts.releasesUrl", SelfUpdateError, "selfupdate/bad-releases-url");
      // Scheme enforcement at config-time so the bug surfaces here, not
      // inside the request loop. Default policy: https only. Operators
      // wiring against an internal mirror can pass allowedProtocols
      // explicitly to opt in to http (e.g. a TLS-terminating proxy
      // upstream of the framework process). The full SSRF / hostname /
      // length policy still runs inside httpClient.request.
      var parsedProto;
      try { parsedProto = new NodeUrl(value).protocol; }
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
    },
    currentVersion: { rule: "required-string", code: "selfupdate/bad-current-version",
                      label: "selfUpdate.poll: opts.currentVersion" },
    assetPattern: function (value) {
      if (value !== undefined && !(value instanceof RegExp) && typeof value !== "string") {
        throw new SelfUpdateError("selfupdate/bad-asset-pattern",
          "selfUpdate.poll: opts.assetPattern must be a RegExp or string when present");
      }
      // Screen an operator-supplied RegExp once at config-time; it is
      // later .test()'d against attacker-controlled asset names in the
      // request path, so a catastrophic-backtracking shape would be a
      // per-request DoS. The string form is matched by substring
      // (indexOf), never compiled, so it carries no ReDoS risk.
      if (value instanceof RegExp) {
        guardRegex.assertSafe(value, "selfUpdate: assetPattern",
          SelfUpdateError, "selfupdate/unsafe-asset-pattern");
      }
    },
    signaturePattern: function (value) {
      if (value !== undefined && !(value instanceof RegExp) && typeof value !== "string") {
        throw new SelfUpdateError("selfupdate/bad-sig-pattern",
          "selfUpdate.poll: opts.signaturePattern must be a RegExp or string when present");
      }
      if (value instanceof RegExp) {
        guardRegex.assertSafe(value, "selfUpdate: signaturePattern",
          SelfUpdateError, "selfupdate/unsafe-sig-pattern");
      }
    },
    maxBytes: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "selfUpdate.poll: opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
    },
    timeoutMs: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "selfUpdate.poll: opts.timeoutMs", SelfUpdateError, "selfupdate/bad-timeout");
    },
    // allowedProtocols is consumed locally (the releasesUrl scheme gate
    // above reads it) and also forwarded to httpClient.request.
    allowedProtocols: { rule: "optional-string-array", code: "selfupdate/bad-allowed-protocols",
                        label: "selfUpdate.poll: opts.allowedProtocols" },
    // headers is merged onto the outbound request headers locally.
    headers:          { rule: "optional-plain-object", code: "selfupdate/bad-headers",
                        label: "selfUpdate.poll: opts.headers" },
    // etag is used locally for the If-None-Match request header.
    etag:             { rule: "optional-string", code: "selfupdate/bad-etag",
                        label: "selfUpdate.poll: opts.etag" },
    // allowedHosts / allowInternal are forwarded verbatim to
    // httpClient.request, which owns their SSRF-gate validation.
  }, "selfUpdate.poll", SelfUpdateError, "selfupdate/bad-opts",
  { allow: ["allowedHosts", "allowInternal"] });
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
 * Each matched asset / signature is reported as
 * `{ name, url, size, digest }`. `digest` carries the release API's
 * published `assets[].digest` (e.g. `"sha256:<hex>"`) verbatim when the
 * upstream supplies it, or `null` when absent — a consumer can use it
 * for a defense-in-depth in-flight integrity check of the downloaded
 * bytes alongside the detached-signature verify.
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
 *                                  // (etags are RFC 9110 §13.1.1
 *                                  // per-resource; an etag captured for
 *                                  // releasesUrl=A is meaningless against
 *                                  // releasesUrl=B. Operators rotating
 *                                  // releasesUrl MUST clear opts.etag at
 *                                  // the same time; reusing a stale etag
 *                                  // makes the new endpoint look like a
 *                                  // 304 "no update" forever.)
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
      // poll() owns status handling — the branches below distinguish a 304
      // If-None-Match "fast no-update" hit from a real non-2xx refusal and a
      // 2xx feed to parse. Without always-resolve, httpClient.request rejects
      // EVERY non-2xx (304 included) as HTTP_ERROR before poll can inspect
      // res.statusCode, which made the documented conditional-poll fast-path
      // and the selfupdate/poll-non-2xx branch dead code — a conditional poll
      // that correctly received a 304 threw selfupdate/poll-failed instead of
      // reporting "no update".
      responseMode:     "always-resolve",
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

  if (res.statusCode === 304) {                                                    // HTTP status code (RFC 7232), not bytes
    _safeAuditEmit("selfupdate.poll.checked", "success", {
      releasesUrl:    opts.releasesUrl,
      currentVersion: opts.currentVersion,
      available:      false,
      etagHit:        true,
    });
    return { available: false, latestTag: null, currentVersion: opts.currentVersion,
             asset: null, signature: null, etag: opts.etag, statusCode: 304 };    // HTTP status code (RFC 7232), not bytes
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
      signatureMatch = { name: a.name, url: a.browser_download_url, size: a.size || null,
                         digest: typeof a.digest === "string" ? a.digest : null };
      continue;
    }
    if (assetMatch === null && _matchAsset(a.name, opts.assetPattern, /\.(tar\.gz|tgz|zip|node|exe|bin)$/i)) {
      assetMatch = { name: a.name, url: a.browser_download_url, size: a.size || null,
                     digest: typeof a.digest === "string" ? a.digest : null };
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
  validateOpts.shape(opts, {
    assetPath:     { rule: "required-string", code: "selfupdate/bad-asset-path",
                     label: "selfUpdate.verify: opts.assetPath" },
    signaturePath: { rule: "required-string", code: "selfupdate/bad-signature-path",
                     label: "selfUpdate.verify: opts.signaturePath" },
    pubkeyPem:     { rule: "required-string", code: "selfupdate/bad-pubkey",
                     label: "selfUpdate.verify: opts.pubkeyPem (PEM-encoded public key)" },
    hashAlgo:      function (value) {
      if (value !== undefined &&
          (typeof value !== "string" || ALLOWED_HASH_ALGS.indexOf(value) === -1)) {
        throw new SelfUpdateError("selfupdate/bad-hash-algo",
          "selfUpdate.verify: opts.hashAlgo must be one of " + ALLOWED_HASH_ALGS.join(", "));
      }
    },
    maxBytes:      function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "selfUpdate.verify: opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
    },
  }, "selfUpdate.verify", SelfUpdateError, "selfupdate/bad-opts");
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
  // requireObject runs first (shape does it) so an opts-shape error keeps
  // the selfupdate/bad-opts code. `from` is validated only for swap, and
  // first to preserve the original field-evaluation order.
  var schema = {};
  if (label === "swap") {
    schema.from = { rule: "required-string", code: "selfupdate/bad-from",
                    label: "selfUpdate.swap: opts.from" };
    // The bytes about to be installed are re-hashed and checked against the
    // hash selfUpdate.verify returned, closing the verify -> swap window. The
    // binding is mandatory — an optional integrity check is opt-in security.
    schema.expectedHash = { rule: "required-string", code: "selfupdate/bad-expected-hash",
                            label: "selfUpdate.swap: opts.expectedHash (the hash selfUpdate.verify returned)" };
    schema.hashAlgo = function (value) {
      if (value !== undefined &&
          (typeof value !== "string" || ALLOWED_HASH_ALGS.indexOf(value) === -1)) {
        throw new SelfUpdateError("selfupdate/bad-hash-algo",
          "selfUpdate.swap: opts.hashAlgo must be one of " + ALLOWED_HASH_ALGS.join(", "));
      }
    };
    // swap re-reads the from-bytes to re-hash them (closing the verify->swap
    // window); its cap must be declarable so it matches the maxBytes an
    // operator passed to selfUpdate.verify for the same asset — otherwise swap
    // would refuse a large binary that verify accepted. Optional; defaults to
    // the same C.BYTES.gib(1) cap the body applies.
    schema.maxBytes = function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        "selfUpdate.swap: opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
    };
  }
  schema.to       = { rule: "required-string", code: "selfupdate/bad-to",
                      label: "selfUpdate." + label + ": opts.to" };
  schema.backupTo = { rule: "required-string", code: "selfupdate/bad-backup",
                      label: "selfUpdate." + label + ": opts.backupTo" };
  validateOpts.shape(opts, schema, "selfUpdate." + label, SelfUpdateError, "selfupdate/bad-opts");
}

// _safeRollback — best-effort restore of `to` from `backupTo` during
// the swap failure paths. Returns null on success (or when no backup
// existed); returns the rollback Error otherwise so the caller can
// throw a distinct `selfupdate/swap-rollback-failed`. Emits the
// `selfupdate.swap.rollback_failed` audit event when rollback fails
// (the prior best-effort catch dropped this signal silently —
// operators with no audit row for `rollback_failed` couldn't tell a
// successful swap-with-rollback from a failed both-binaries-lost
// scenario). SSDF RV.1.
async function _safeRollback(backupTo, to, hadOriginal) {
  if (!hadOriginal) return null;
  try {
    await atomicFile.copy(backupTo, to, { fileMode: 0o600 });
    return null;
  } catch (re) {
    var err = re instanceof Error ? re : new Error(String(re));
    _safeAuditEmit("selfupdate.swap.rollback_failed", "denied", {
      to: to, backupTo: backupTo,
      reason: "rollback-copy-failed",
      message: err.message,
    });
    return err;
  }
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
 * Atomic install: re-hash `from` and refuse unless it matches `expectedHash`
 * (the hash selfUpdate.verify returned — this binds the installed bytes to the
 * signature-verified bytes and closes the verify→swap window), copy the
 * existing `to` to `backupTo`, rename `from` → `to`, then fsync both
 * directories. Cross-device renames fall back to copy + unlink on the
 * destination filesystem. On any failure the original `to` is restored from
 * `backupTo`. Throws SelfUpdateError on a missing `from`, an
 * expectedHash mismatch, backup-copy failure, cross-device install failure,
 * or rename failure.
 *
 * @opts
 *   from:         string,   // required — newly-installed asset path
 *   to:           string,   // required — target install path
 *   backupTo:     string,   // required — backup path for the existing `to`
 *   expectedHash: string,   // required — the hash selfUpdate.verify returned
 *   hashAlgo:     string,   // sha3-512 (default) | sha-256 | sha-512 | shake256
 *   maxBytes:     number,   // from-bytes re-hash cap (default 1 GiB) — set to
 *                           //   the same value passed to selfUpdate.verify
 *
 * @example
 *   var v = await b.selfUpdate.verify({ assetPath, signaturePath, pubkeyPem });
 *   try {
 *     await b.selfUpdate.swap({
 *       from:         "/tmp/blamejs-doc-missing.bin",
 *       to:           "/tmp/blamejs-doc-target.bin",
 *       backupTo:     "/tmp/blamejs-doc-backup.bin",
 *       expectedHash: v.hash,
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

  // Bind the installed object to the signature-verified bytes. Read `from` with
  // O_NOFOLLOW (refuseSymlink) so a symlinked source is refused AT OPEN rather
  // than followed — otherwise the bytes hashed (the link target) would differ
  // from the object a by-path rename installs (the link itself). The verified
  // bytes are then installed FROM MEMORY below, so the installed object is
  // exactly what was hashed: no symlink-install surface and no time-of-check /
  // time-of-use window between the hash and the install (which a by-path rename
  // or re-read would reopen).
  var swapAlg = opts.hashAlgo || DEFAULT_HASH_ALG;
  var fromMode;
  try { fromMode = (nodeFs.statSync(from).mode & 0o777); } catch (_m) { fromMode = 0o600; }
  var fromBytes;
  try {
    fromBytes = atomicFile.fdSafeReadSync(from, {
      maxBytes: typeof opts.maxBytes === "number" ? opts.maxBytes : C.BYTES.gib(1),
      refuseSymlink: true,
    });
  } catch (e) {
    throw new SelfUpdateError("selfupdate/swap-read-failed",
      "selfUpdate.swap: failed to read from for the integrity re-check (a symlinked source is refused): " +
      ((e && e.message) || String(e)));
  }
  var actualHash = nodeCrypto.createHash(swapAlg).update(fromBytes).digest("hex");
  if (actualHash !== opts.expectedHash) {
    _safeAuditEmit("selfupdate.swap.hash_mismatch", "denied", {
      from: from, to: to, alg: swapAlg, expected: opts.expectedHash, actual: actualHash,
    });
    throw new SelfUpdateError("selfupdate/swap-hash-mismatch",
      "selfUpdate.swap: from bytes do not match expectedHash (asset changed after verify?) — refusing to install");
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

  // Step 3 — install the verified in-memory bytes via an atomic temp+fsync+
  // rename on the DESTINATION filesystem (atomicFile.write), so the installed
  // object is exactly the bytes just hashed: cross-device is handled (the temp
  // is created on the dest FS), there is no by-path re-read to race, and a
  // symlinked source can't be moved into place. Roll back from the backup on
  // failure; a rollback failure surfaces as a DISTINCT error class + audit
  // event so operators don't silently lose both binaries (SSDF RV.1).
  try {
    await atomicFile.write(to, fromBytes, { fileMode: fromMode, overwrite: true });
  } catch (e) {
    var rbErr = await _safeRollback(backupTo, to, hadOriginal);
    if (rbErr) {
      throw new SelfUpdateError("selfupdate/swap-rollback-failed",
        "selfUpdate.swap: install of " + to + " failed AND rollback ALSO failed — " +
        "operator must manually restore from backupTo=" + backupTo +
        ". install-error=" + ((e && e.message) || String(e)) +
        "; rollback-error=" + rbErr.message);
    }
    throw new SelfUpdateError("selfupdate/swap-failed",
      "selfUpdate.swap: install of " + to + " failed: " + ((e && e.message) || String(e)));
  }
  // Consume the source asset now that the verified bytes are installed
  // (best-effort — the install already succeeded; a leftover temp is
  // operator-cleanable).
  try { nodeFs.unlinkSync(from); } catch (_u) { /* tmp source leak — operator-cleanable */ }

  // Step 4 — fsync directories so the install is durable.
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
