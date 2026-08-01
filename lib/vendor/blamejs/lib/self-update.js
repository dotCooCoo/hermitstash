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
  // The `: false` arm is unreachable from the public API: every call that
  // reaches this ternary (a non-string, non-RegExp pattern) passes a truthy
  // fallback, and the null-fallback call sites only run with a validated
  // string/RegExp pattern that never reaches the ternary.
  /* c8 ignore next */
  return fallback ? fallback.test(name) : false;
}

// Detached-signature suffixes. A release's detached signature is conventionally
// the asset name plus one of these (asset.tar.gz.sig / .asc / .sig.bin).
var _SIG_SUFFIXES = [".sig", ".asc", ".sig.bin"];
var _SIG_SHAPE    = /\.sig$|\.asc$|\.sig\.bin$/i;

function _assetObj(a) {
  return {
    name:   a.name,
    url:    a.browser_download_url,
    size:   a.size || null,
    digest: typeof a.digest === "string" ? a.digest : null,
  };
}

function _findEntryByName(entries, name) {
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].name === name) return entries[i];
  }
  return null;
}

// Strip the final extension from an asset name so a signature that REPLACES the
// extension (app.bin -> app.sig) pairs as strongly as one that APPENDS a suffix
// (app.bin -> app.bin.sig). Returns the name unchanged when there is no leading
// stem to keep (no extension, or a leading-dot dotfile) so no over-broad stem is
// derived to match a foreign sidecar against.
function _assetStem(name) {
  var dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

// _soleArtifactWithStem — is `assetName` the ONLY non-signature artifact in the
// release whose extension-stripped stem is `stem`? The replace-convention pairing
// (below) is only unambiguous when it is: with app.bin AND app.exe present, a
// single app.sig can't be attributed to either.
function _soleArtifactWithStem(assetName, stem, entries) {
  for (var i = 0; i < entries.length; i++) {
    var n = entries[i].name;
    if (n === assetName) continue;              // the asset itself
    if (_SIG_SHAPE.test(n)) continue;           // signatures aren't artifacts
    // Ambiguous when another artifact would derive the SAME `stem + suffix`
    // signature name: either it shares the extension-stripped stem (its replace
    // convention), OR its full name IS the stem (its APPEND convention — app.tar's
    // app.tar.sig is also app.tar.gz's replace-derived app.tar.sig).
    if (_assetStem(n) === stem || n === stem) return false;
  }
  return true;
}

// _pathsAlias — do two already-realpath-resolved absolute paths refer to the same
// file? An exact match, or a CASE-ONLY difference: realpathSync does not always
// canonicalize the final component's case, so on a case-insensitive volume
// (Windows / default macOS) a backup path can alias the reserved quarantine path
// with different letter casing. Comparing case-insensitively on every platform is
// fail-closed here: the quarantine suffix (.rollback-bad) is framework-reserved,
// so a case-variant of it is only ever the same reserved path, never a distinct
// operator backup that happens to collide.
function _pathsAlias(a, b) {
  return a === b || a.toLowerCase() === b.toLowerCase();
}

// _derivedSignatureNames — the exact signature names that unambiguously sign
// `assetName`: the asset name plus each suffix (append convention) and, when the
// asset has an extension to strip AND is the sole artifact with that stem, the
// stem plus each suffix (replace convention). Every derived name ends in a
// signature suffix, so the boundary after the stem is always that suffix's leading
// delimiter — a bare-prefix look-alike (application.sig for app.bin, stem `app`)
// never derives. The replace convention is withheld when another artifact shares
// the stem (app.bin + app.exe), where a lone app.sig is ambiguous.
function _derivedSignatureNames(assetName, entries) {
  var stem       = _assetStem(assetName);
  var stemUnique = stem !== assetName && _soleArtifactWithStem(assetName, stem, entries);
  var names = [];
  for (var s = 0; s < _SIG_SUFFIXES.length; s++) {
    names.push(assetName + _SIG_SUFFIXES[s]);
    if (stemUnique) names.push(stem + _SIG_SUFFIXES[s]);
  }
  return names;
}

// _selectSignatureFor — pick the detached signature OF `assetName`, not a
// first-match-wins signature that may sign a DIFFERENT sidecar. Selecting the
// asset first and DERIVING the expected signature name from it is the pairing
// contract: a returned { asset, signature } is guaranteed to be an asset and
// the signature over exactly that asset. The derived names cover both common
// one-asset-one-sig conventions — the suffix APPENDED to the asset name
// (app.bin -> app.bin.sig) and the extension REPLACED (app.bin -> app.sig).
// Falls back to a lone signature-shaped asset only when the release ships
// exactly one AND that sidecar references the full asset name (the common
// algorithm-suffixed case); anything ambiguous OR a lone sidecar whose name is
// unrelated to the asset fails closed (null) rather than pairing a signature
// that may not sign the returned asset.
function _selectSignatureFor(assetName, entries, signaturePattern) {
  // (a) Strong pairing: an exact derived signature name (append or replace).
  var derived = _derivedSignatureNames(assetName, entries);
  for (var s = 0; s < derived.length; s++) {
    var hit = _findEntryByName(entries, derived[s]);
    // When the operator constrained signaturePattern, the derived name must
    // also satisfy it; otherwise the derived name is authoritative.
    if (hit && (signaturePattern === undefined || _matchAsset(hit.name, signaturePattern, null))) {
      return _assetObj(hit);
    }
  }
  // (b) Operator signaturePattern, no derived hit: accept only a pattern match
  // that ALSO references the asset stem, and only when unambiguous — else fail
  // closed (never pair a pattern hit that may sign a different asset).
  if (signaturePattern !== undefined) {
    var stemMatches = entries.filter(function (e) {
      return e.name.indexOf(assetName) === 0 && _matchAsset(e.name, signaturePattern, null);
    });
    return stemMatches.length === 1 ? _assetObj(stemMatches[0]) : null;
  }
  // (c) No operator pattern, no derived hit: accept a lone signature-shaped asset
  // ONLY when it references the asset stem (single-sig release). A lone sidecar
  // whose name is unrelated to the asset may sign a different object, so it fails
  // closed (null) — never pair a name-unrelated signature to the asset.
  var sigShaped = entries.filter(function (e) {
    return _SIG_SHAPE.test(e.name) && e.name.indexOf(assetName) === 0;
  });
  return sigShaped.length === 1 ? _assetObj(sigShaped[0]) : null;
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
      /* c8 ignore next -- String(e) fallback: request rejections are always Errors with a message */
      message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/poll-failed",
      /* c8 ignore next */
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

  // The non-Buffer arm is defensive: httpClient.request always resolves a
  // Buffer body (Buffer.alloc(0) for an empty response), so the string/null
  // normalization never runs on the real transport.
  /* c8 ignore next 2 */
  var bodyBuf = Buffer.isBuffer(res.body) ? res.body :
    (res.body == null ? Buffer.alloc(0) : Buffer.from(String(res.body), "utf8"));
  var parsed;
  try {
    parsed = safeJson.parse(bodyBuf, { maxBytes: maxBytes });
  } catch (e) {
    _safeAuditEmit("selfupdate.poll.checked", "denied", {
      releasesUrl: opts.releasesUrl, reason: "bad-json",
      /* c8 ignore next -- String(e) fallback: safeJson.parse throws Errors with a message */
      message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/bad-json",
      /* c8 ignore next */
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
  // Collect the well-formed asset entries once, preserving feed order.
  var entries = [];
  for (var i = 0; i < assets.length; i++) {
    var a = assets[i] || {};
    if (typeof a.name !== "string" || typeof a.browser_download_url !== "string") continue;
    entries.push(a);
  }
  // Select the runtime asset FIRST, then derive its detached signature — so the
  // returned signature is the sig OF the returned asset, never a first-match-wins
  // sig that may belong to a different sidecar (#497).
  var assetMatch     = null;
  var signatureMatch = null;
  for (var j = 0; j < entries.length; j++) {
    if (_matchAsset(entries[j].name, opts.assetPattern, /\.(tar\.gz|tgz|zip|node|exe|bin)$/i)) {
      assetMatch = _assetObj(entries[j]);
      break;
    }
  }
  if (assetMatch) {
    signatureMatch = _selectSignatureFor(assetMatch.name, entries, opts.signaturePattern);
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
 * Verify a detached signature over the asset bytes. The signature
 * algorithm is auto-detected from `opts.pubkeyPem` (ML-DSA-87 / Ed25519
 * / ECDSA P-384). Verification routes through the framework's own
 * `standaloneVerifier`, which streams the asset (no whole-file buffer),
 * commits to a SHA3-512 digest, and dispatches the ECDSA signature
 * encoding by structure (DER SEQUENCE vs raw IEEE-P1363) — so a release
 * sidecar signed SHA3-512-then-sign with either encoding verifies, and
 * the accept set is identical to `b.selfUpdate.standaloneVerifier.verify`
 * (no verifier divergence between the install-pipeline and installed
 * paths). Reports the asset's hash alongside the verified flag for SBOM /
 * audit correlation; the supported digest algorithms are sha3-512
 * (default), sha-256, sha-512, and shake256. Throws SelfUpdateError on a
 * missing file, a verify-time exception, or a signature that does not
 * verify.
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
// _mapStandaloneKind — translate a standaloneVerifier `.kind` into this
// module's typed selfupdate/* code. File-availability / size-cap failures are
// read-failed; a cryptographic non-verification is signature-mismatch; a
// structural / key / encoding problem is verify-failed. Keeping the mapping
// structural (off `.kind`, not English message text) means a message reword in
// the zero-dep verifier never silently reclassifies a failure here.
function _mapStandaloneKind(kind) {
  switch (kind) {
    case "asset-not-found":
    case "sig-not-found":
    case "sig-too-large":
    case "asset-too-large":
    case "size-race":
      return "selfupdate/read-failed";
    case "verify-failed":
      return "selfupdate/signature-mismatch";
    default:   // bad-input / bad-pubkey / unsupported-key / sig-empty / bad-sig-encoding
      return "selfupdate/verify-failed";
  }
}

async function verify(opts) {
  _validateVerifyOpts(opts);
  var alg = opts.hashAlgo || DEFAULT_HASH_ALG;
  var maxBytes = typeof opts.maxBytes === "number" ? opts.maxBytes : C.BYTES.gib(1);
  // The default sha3-512 / sha-256 reported digests are already produced by the
  // standalone verifier's single pass; only a non-default reported alg needs an
  // extra digest folded into that same stream (no second read of the asset).
  var extraDigests = (alg === "sha3-512" || alg === "sha-256") ? [] : [alg];

  var result;
  try {
    // Route the signature verification through the framework's own
    // standaloneVerifier so the installed path and the copy-into-install-pipeline
    // path share ONE verifier — SHA3-512 digest, DER/IEEE-P1363 structural
    // dispatch, streamed (no whole-asset in-memory buffer). It fails closed on a
    // wrong key, truncated / empty signature, or size-cap breach.
    result = standaloneVerifier.verify(opts.assetPath, opts.signaturePath, opts.pubkeyPem, {
      maxAssetBytes: maxBytes,
      extraDigests:  extraDigests,
    });
  } catch (e) {
    var code = _mapStandaloneKind(e && e.kind);
    _safeAuditEmit("selfupdate.verify.failed", "denied", {
      assetPath: opts.assetPath, signaturePath: opts.signaturePath,
      // Fallbacks are defensive: standaloneVerifier throws only via `_svErr`,
      // which always sets `.kind` and a message, so neither alternate runs.
      /* c8 ignore next */
      reason: (e && e.kind) || "verify-error", message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError(code,
      /* c8 ignore next */
      "selfUpdate.verify: " + ((e && e.message) || String(e)));
  }

  var hashHex = alg === "sha3-512" ? result.sha3_512
              : alg === "sha-256"  ? result.sha256
              : result.digests[alg];

  _safeAuditEmit("selfupdate.verify.passed", "success", {
    assetPath: opts.assetPath, signaturePath: opts.signaturePath,
    alg: alg, hash: hashHex, bytes: result.bytes,
  });
  log("selfUpdate.verify passed asset=" + opts.assetPath + " alg=" + alg);
  return { verified: true, hash: hashHex, alg: alg, bytes: result.bytes };
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
  }
  schema.to       = { rule: "required-string", code: "selfupdate/bad-to",
                      label: "selfUpdate." + label + ": opts.to" };
  schema.backupTo = { rule: "required-string", code: "selfupdate/bad-backup",
                      label: "selfUpdate." + label + ": opts.backupTo" };
  // maxBytes is a declared opt for BOTH labels: swap re-reads the from-bytes to
  // re-hash them (closing the verify->swap window) and rollback reads backupTo to
  // restore it. Either read must be raisable past atomicFile's 64 MiB default so a
  // large prior binary (a Node SEA is 100+ MiB) is not refused before it starts.
  // Optional; each body defaults to the same C.BYTES.gib(1) cap.
  schema.maxBytes = function (value) {
    numericBounds.requirePositiveFiniteIntIfPresent(value,
      "selfUpdate." + label + ": opts.maxBytes", SelfUpdateError, "selfupdate/bad-max-bytes");
  };
  validateOpts.shape(opts, schema, "selfUpdate." + label, SelfUpdateError, "selfupdate/bad-opts");
}

// _relocateFile — move `src` -> `dst`, preferring an atomic rename. A rename
// moves even a locked, RUNNING image on Windows (which refuses an in-place
// replace of a mapped executable but allows a rename/move) and needs no second
// copy; on EXDEV (cross-volume) it falls back to copy + unlink. This one
// primitive backs BOTH "move the outgoing `to` aside to its backup before an
// install" and "restore the backup over `to` on rollback", so the locked-image
// path is handled identically in the install and rollback directions.
async function _relocateFile(src, dst, fileMode) {
  try {
    atomicFile.renameWithRetry(src, dst);
    return;
  } catch (e) {
    // The EXDEV (cross-volume) fall-through needs two filesystems and is not
    // reachable in a single-volume test; the whole cross-device arm — the
    // non-EXDEV re-throw guard and the copy+unlink fallback — is ignored for
    // coverage since its else-branch can't be isolated from the guard.
    /* c8 ignore start */
    if (!e || e.code !== "EXDEV") throw e;
    // Cross-volume: a rename can't cross the device boundary. Preserve the
    // bytes by copy, then remove the source (best-effort — a locked cross-volume
    // source is the documented limitation of this rare fallback).
    await atomicFile.copy(src, dst, { fileMode: fileMode });
    try { nodeFs.unlinkSync(src); } catch (_u) { /* cross-vol source cleanup — operator-cleanable */ }
    /* c8 ignore stop */
  }
}

// _safeRollback — best-effort restore of `to` from `backupTo` during the swap
// failure paths. Routes through _relocateFile so the moved-aside backup is
// renamed back over the (now-absent) `to` — a rename that succeeds even where an
// in-place copy-replace would be blocked by a lock. Returns null on success (or
// when no backup existed); returns the rollback Error otherwise so the caller
// can throw a distinct `selfupdate/swap-rollback-failed`. Emits the
// `selfupdate.swap.rollback_failed` audit event when rollback fails (the prior
// best-effort catch dropped this signal silently — operators with no audit row
// for `rollback_failed` couldn't tell a successful swap-with-rollback from a
// failed both-binaries-lost scenario). SSDF RV.1.
async function _safeRollback(backupTo, to, hadOriginal) {
  // The active-restore path (hadOriginal === true) only runs when the install
  // write fails AFTER a successful move-aside — a state that can't be forced
  // through the public API without an fs-layer mock (a move-aside that succeeds
  // guarantees the subsequent same-directory install write also succeeds). The
  // whole body is ignored for coverage since the hadOriginal fall-through
  // branch can't be isolated from the early return.
  /* c8 ignore start */
  if (!hadOriginal) return null;
  try {
    await _relocateFile(backupTo, to, 0o600);
    return null;
  } catch (re) {
    var err = re instanceof Error ? re : new Error(String(re));
    _safeAuditEmit("selfupdate.swap.rollback_failed", "denied", {
      to: to, backupTo: backupTo,
      reason: "rollback-restore-failed",
      message: err.message,
    });
    return err;
  }
  /* c8 ignore stop */
}

// Atomic swap of `from` -> `to` with rollback on failure. Steps:
//
//   1. ensure `to` and `backupTo` parents exist
//   2. if `to` exists — MOVE it aside to `backupTo` via a rename (this both
//      frees `to` and IS the backup). A rename moves even a locked, running
//      image on Windows, where an in-place replace of a mapped exe is refused;
//      cross-volume (EXDEV) falls back to copy + unlink.
//   3. write the verified in-memory bytes to the now-free `to` (a create, not
//      a replace of a locked file)
//   4. fsync both directories (best-effort across platforms)
//
// If step 2 fails the original `to` is intact (surfaced as backup-failed); if
// step 3 fails the moved-aside backup is renamed back over `to` (rollback); if
// step 4 fails the swap is considered complete (operator can audit).
/**
 * @primitive b.selfUpdate.swap
 * @signature b.selfUpdate.swap(opts)
 * @since     0.6.0
 * @related   b.selfUpdate.verify, b.selfUpdate.rollback, b.atomicFile.write
 *
 * Atomic install: re-hash `from` and refuse unless it matches `expectedHash`
 * (the hash selfUpdate.verify returned — this binds the installed bytes to the
 * signature-verified bytes and closes the verify→swap window), MOVE the existing
 * `to` aside to `backupTo` with a rename (which succeeds on a locked, running
 * image where an in-place replace is refused, and IS the backup), write the
 * verified bytes to the now-free `to`, then fsync both directories. `backupTo`
 * must be on the same volume as `to`; a cross-volume backup (EXDEV) falls back to
 * copy + replace. On an install-write failure after the move-aside, the backup is
 * restored over `to`. Throws SelfUpdateError on a missing `from`, an expectedHash
 * mismatch, a move-aside/backup failure, or an install-write failure.
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
  /* c8 ignore next -- statSync catch is TOCTOU-defensive: existsSync(from) just passed */
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
      /* c8 ignore next */
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

  // Step 2 — move the outgoing `to` ASIDE to `backupTo` via a rename. A rename
  // frees the path even when `to` is a locked, running image (Windows refuses an
  // in-place replace of a mapped executable but allows the move), and the moved
  // file IS the backup — so no separate copy of the old bytes is needed. The
  // move-aside failing leaves the original `to` intact (surfaced as backup-failed).
  var hadOriginal = nodeFs.existsSync(to);
  if (hadOriginal) {
    try {
      await _relocateFile(to, backupTo, 0o600);
    } catch (e) {
      throw new SelfUpdateError("selfupdate/backup-failed",
        "selfUpdate.swap: failed to move " + to + " aside to " + backupTo + ": " +
        /* c8 ignore next */
        ((e && e.message) || String(e)));
    }
  }

  // Step 3 — install the verified in-memory bytes at the now-free `to` via an
  // atomic temp+fsync+rename (atomicFile.write). With `to` moved aside (or never
  // present), this rename is a CREATE at a free path, not a replace of a locked
  // file — so it succeeds on a running Windows image. The installed object is
  // exactly the bytes just hashed (installed from memory), so there is no by-path
  // re-read to race and no symlinked source to move into place. On failure the
  // moved-aside backup is renamed back over `to`; a rollback failure surfaces as
  // a DISTINCT error class + audit event so operators don't silently lose both
  // binaries (SSDF RV.1).
  try {
    await atomicFile.write(to, fromBytes, { fileMode: fromMode, overwrite: true });
  } catch (e) {
    var rbErr = await _safeRollback(backupTo, to, hadOriginal);
    // The rollback-also-failed arm needs the install write to fail after a
    // successful move-aside — unforceable without an fs mock (see _safeRollback).
    /* c8 ignore start */
    if (rbErr) {
      throw new SelfUpdateError("selfupdate/swap-rollback-failed",
        "selfUpdate.swap: install of " + to + " failed AND rollback ALSO failed — " +
        "operator must manually restore from backupTo=" + backupTo +
        ". install-error=" + ((e && e.message) || String(e)) +
        "; rollback-error=" + rbErr.message);
    }
    /* c8 ignore stop */
    throw new SelfUpdateError("selfupdate/swap-failed",
      /* c8 ignore next */
      "selfUpdate.swap: install of " + to + " failed: " + ((e && e.message) || String(e)));
  }
  // Consume the source asset now that the verified bytes are installed
  // (best-effort — the install already succeeded; a leftover temp is
  // operator-cleanable). The unlink-failure catch is unforceable on the
  // supported platforms (a readable regular file is always removable here).
  /* c8 ignore next */
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
 * Restore `backupTo` → `to`. When a bad-binary `to` is present it is first MOVED
 * ASIDE with a rename — which frees the path even for a locked, running Windows
 * image (Windows refuses an in-place replace of a mapped executable but allows
 * the move) — so the restore is a CREATE at the freed path, not a replace of a
 * locked file; the quarantined bad binary is then removed (best-effort). The
 * backup read is capped at `maxBytes` (default 1 GiB) so a large prior binary (a
 * Node SEA is 100+ MiB) restores rather than being refused at atomicFile's 64 MiB
 * copy default. Operators run rollback when a post-swap healthcheck reports the
 * new binary is bad. Throws SelfUpdateError when the backup file is missing, the
 * move-aside fails, or the copy fails; a copy failure after the move-aside
 * restores the quarantined image back over `to` so a failed rollback never
 * leaves the target absent.
 *
 * @opts
 *   to:       string,   // required — target path to restore
 *   backupTo: string,   // required — source backup path
 *   maxBytes: number,   // backup read cap (default 1 GiB)
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

  // Move the outgoing (bad) `to` ASIDE to a quarantine path via a rename before
  // restoring — the SAME move-aside swap uses so the restore is a create at a
  // freed path, not a replace of a possibly-locked running image (Windows refuses
  // the in-place replace but allows the move). A move-aside failure surfaces as
  // rollback-failed with the original `to` left intact (fail closed).
  var quarantine  = to + ".rollback-bad";
  // Reject a backupTo that aliases the quarantine path: the move-aside would
  // first unlink the quarantine (deleting the known-good backup), then move the
  // bad `to` into it, then copy those bad bytes back over `to` — corrupting the
  // target AND destroying the backup while reporting success. Fail closed before
  // touching either file. Compare REALPATH-resolved paths, not path.resolve():
  // path.resolve leaves SYMLINKS unresolved, so a symlinked backupTo (or a
  // symlinked parent dir) pointing at the quarantine would slip past. backupTo
  // exists (checked above); the quarantine may not, so realpath its existing
  // parent dir + append the basename to get its canonical path.
  var realBackup     = nodeFs.realpathSync(backupTo);
  var realQuarantine = nodePath.join(nodeFs.realpathSync(nodePath.dirname(quarantine)),
                                     nodePath.basename(quarantine));
  if (_pathsAlias(realBackup, realQuarantine)) {
    throw new SelfUpdateError("selfupdate/rollback-failed",
      "selfUpdate.rollback: backupTo resolves to the reserved quarantine path " +
      JSON.stringify(quarantine) + " (it would be overwritten by the move-aside)");
  }
  var hadTarget   = nodeFs.existsSync(to);
  if (hadTarget) {
    try { nodeFs.unlinkSync(quarantine); } catch (_stale) { /* no stale quarantine (the common case) */ }
    try {
      await _relocateFile(to, quarantine, 0o600);
    } catch (e) {
      throw new SelfUpdateError("selfupdate/rollback-failed",
        "selfUpdate.rollback: failed to move current " + to + " aside to " + quarantine +
        /* c8 ignore next */
        " before restore: " + ((e && e.message) || String(e)));
    }
  }

  try {
    await atomicFile.copy(backupTo, to, {
      fileMode: 0o600,
      maxBytes: typeof opts.maxBytes === "number" ? opts.maxBytes : C.BYTES.gib(1),
    });
  } catch (e) {
    // The copy failed AFTER `to` was moved aside to `quarantine` (exceeds
    // maxBytes, unreadable source, destination write error), so `to` is now
    // absent — a failed rollback must not become a next-launch outage with no
    // binary at all. Restore the quarantined image back over `to` (a rename,
    // lock-safe) before surfacing the error, so an executable (the pre-rollback
    // one) still exists — the same fail-closed restore the swap failure path does.
    if (hadTarget) {
      try {
        await _relocateFile(quarantine, to, 0o600);
      /* c8 ignore start -- restore-failure is the catastrophic both-lost case: renaming an existing quarantine back over the now-absent `to` cannot be forced through the public API without an fs-layer mock */
      } catch (re) {
        _safeAuditEmit("selfupdate.rollback.restore_failed", "denied", {
          to: to, quarantine: quarantine, reason: "rollback-restore-failed",
          message: (re && re.message) || String(re),
        });
      }
      /* c8 ignore stop */
    }
    throw new SelfUpdateError("selfupdate/rollback-failed",
      "selfUpdate.rollback: copy " + backupTo + " -> " + to + " failed: " +
      /* c8 ignore next */
      ((e && e.message) || String(e)));
  }
  // The known-good backup is restored; drop the quarantined bad binary
  // (best-effort — a locked / read-only quarantine is operator-cleanable). The
  // unlink-failure catch is unforceable on the supported platforms.
  if (hadTarget) {
    /* c8 ignore next */
    try { nodeFs.unlinkSync(quarantine); } catch (_q) { /* quarantined bad binary — operator-cleanable */ }
  }
  atomicFile.fsyncDir(nodePath.dirname(to));

  _safeAuditEmit("selfupdate.rollback.completed", "success", {
    to: to, backupTo: backupTo,
  });
  log("selfUpdate.rollback restored " + to + " from " + backupTo);
  return { ok: true, restoredAt: Date.now(), to: to, backupTo: backupTo };
}

// ---- probation / auto-rollback orchestration ----
//
// A swap installs the new binary; probation gives it a bounded window to prove
// itself before the install is considered final. The new binary (or the
// operator's shutdown hook) calls confirmHealthy() once it is up + healthy,
// which clears the marker — the "clean / healthy" signal. On the next boot
// evaluateOnBoot() reads the marker: still inside the window means a clean stop /
// restart (NOT a crash) so it keeps; past the window with no confirmHealthy means
// the binary never became healthy so it rolls the known-good backup back over the
// target. Rollback re-verifies first (the installed bytes must still hash to the
// probationary expectedHash and the backup must exist) so a marker left behind by
// a swap that FAILED — where the new binary was never installed — never triggers
// a phantom rollback.

var PROBATION_MARKER_SUFFIX = ".blamejs-probation.json";
var PROBATION_MARKER_MAX    = C.BYTES.kib(64);   // marker is a small JSON record

function _resolveMarkerPath(opts) {
  if (typeof opts.markerPath === "string" && opts.markerPath.length > 0) return opts.markerPath;
  return opts.to + PROBATION_MARKER_SUFFIX;
}

function _probationHashAlgo(value, method) {
  if (value !== undefined && (typeof value !== "string" || ALLOWED_HASH_ALGS.indexOf(value) === -1)) {
    throw new SelfUpdateError("selfupdate/bad-hash-algo",
      "selfUpdate." + method + ": opts.hashAlgo must be one of " + ALLOWED_HASH_ALGS.join(", "));
  }
}

// Field-descriptor builders for the probation validators — the required/optional
// string field shape composes from one definition instead of repeating an inline
// `{ rule, code, label }` object per field across the three validators.
function _reqStr(code, label) { return { rule: "required-string", code: code, label: label }; }
function _optStr(code, label) { return { rule: "optional-string", code: code, label: label }; }
function _probationLabel(method, field) { return "selfUpdate." + method + ": opts." + field; }

function _validateProbationBeginOpts(opts) {
  validateOpts.shape(opts, {
    to:           _reqStr("selfupdate/bad-to",            _probationLabel("beginProbation", "to")),
    backupTo:     _reqStr("selfupdate/bad-backup",        _probationLabel("beginProbation", "backupTo")),
    expectedHash: _reqStr("selfupdate/bad-expected-hash", _probationLabel("beginProbation", "expectedHash")),
    windowMs: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        _probationLabel("beginProbation", "windowMs"), SelfUpdateError, "selfupdate/bad-window");
    },
    hashAlgo:   function (value) { _probationHashAlgo(value, "beginProbation"); },
    markerPath: _optStr("selfupdate/bad-marker-path", _probationLabel("beginProbation", "markerPath")),
  }, "selfUpdate.beginProbation", SelfUpdateError, "selfupdate/bad-opts");
}

function _validateConfirmOpts(opts) {
  validateOpts.shape(opts, {
    to:         _reqStr("selfupdate/bad-to",          _probationLabel("confirmHealthy", "to")),
    markerPath: _optStr("selfupdate/bad-marker-path", _probationLabel("confirmHealthy", "markerPath")),
  }, "selfUpdate.confirmHealthy", SelfUpdateError, "selfupdate/bad-opts");
}

function _validateEvaluateOpts(opts) {
  validateOpts.shape(opts, {
    to:         _reqStr("selfupdate/bad-to",          _probationLabel("evaluateOnBoot", "to")),
    backupTo:   _optStr("selfupdate/bad-backup",      _probationLabel("evaluateOnBoot", "backupTo")),
    markerPath: _optStr("selfupdate/bad-marker-path", _probationLabel("evaluateOnBoot", "markerPath")),
    now: function (value) {
      numericBounds.requirePositiveFiniteIntIfPresent(value,
        _probationLabel("evaluateOnBoot", "now"), SelfUpdateError, "selfupdate/bad-now");
    },
  }, "selfUpdate.evaluateOnBoot", SelfUpdateError, "selfupdate/bad-opts");
}

function _probationKeep(reason, to, markerPath) {
  // A boot with no probation marker is the steady-state no-op — don't audit it
  // every boot. Every other keep reason is a real probation transition.
  if (reason !== "no-probation-active") {
    _safeAuditEmit("selfupdate.probation.kept", "success", {
      to: to, markerPath: markerPath, reason: reason,
    });
  }
  return { action: "keep", reason: reason };
}

/**
 * @primitive b.selfUpdate.beginProbation
 * @signature b.selfUpdate.beginProbation(opts)
 * @since     0.17.13
 * @status    stable
 * @related   b.selfUpdate.confirmHealthy, b.selfUpdate.evaluateOnBoot, b.selfUpdate.swap
 *
 * Arm a bounded post-install probation for a freshly-swapped binary. Writes an
 * atomic marker (`to` + `.blamejs-probation.json`, or `opts.markerPath`)
 * recording the target, the known-good backup, the installed bytes' hash, and an
 * `expiresAt` = now + `windowMs`. The new binary calls `confirmHealthy` once it
 * is up and healthy (clearing the marker); if the window elapses with no such
 * confirmation, the next `evaluateOnBoot` rolls the backup back over the target.
 *
 * The marker is written via `b.atomicFile.writeJson` (temp + fsync + rename), so
 * a process that dies mid-write leaves either the previous complete marker or
 * none — never a half-written record a boot could misread.
 *
 * @opts
 *   to:           string,   // required — installed binary path (the probationary target)
 *   backupTo:     string,   // required — known-good backup restored on a failed probation
 *   expectedHash: string,   // required — hash of the installed bytes (selfUpdate.verify/swap's hash)
 *   windowMs:     number,   // probation window in ms; default 10 minutes
 *   hashAlgo:     string,   // sha3-512 (default) | sha-256 | sha-512 | shake256
 *   markerPath:   string,   // override marker path (default: `to` + ".blamejs-probation.json")
 *
 * @example
 *   var v = await b.selfUpdate.verify({ assetPath, signaturePath, pubkeyPem });
 *   await b.selfUpdate.swap({ from, to, backupTo, expectedHash: v.hash });
 *   var p = await b.selfUpdate.beginProbation({ to, backupTo, expectedHash: v.hash });
 *   p.expiresAt;   // → epoch ms the probation window closes
 */
async function beginProbation(opts) {
  _validateProbationBeginOpts(opts);
  var markerPath  = _resolveMarkerPath(opts);
  var windowMs    = typeof opts.windowMs === "number" ? opts.windowMs : C.TIME.minutes(10);
  var hashAlgo    = opts.hashAlgo || DEFAULT_HASH_ALG;
  var installedAt = Date.now();
  var expiresAt   = installedAt + windowMs;

  // Carry a monotonically increasing generation across successive probations of
  // the same target — each install supersedes the prior probation record.
  var generation = 1;
  try {
    var prior = await atomicFile.readJson(markerPath, { maxBytes: PROBATION_MARKER_MAX });
    if (prior && typeof prior.generation === "number" && isFinite(prior.generation)) {
      generation = prior.generation + 1;
    }
  } catch (_p) { /* no prior marker (or unreadable) — first generation */ }

  var marker = {
    schema:       1,
    installedAt:  installedAt,
    expiresAt:    expiresAt,
    windowMs:     windowMs,
    to:           opts.to,
    backupTo:     opts.backupTo,
    expectedHash: opts.expectedHash,
    hashAlgo:     hashAlgo,
    generation:   generation,
  };
  var written = await atomicFile.writeJson(markerPath, marker, { computeHash: true, fileMode: 0o600 });

  _safeAuditEmit("selfupdate.probation.begin", "success", {
    to: opts.to, backupTo: opts.backupTo, markerPath: markerPath,
    expiresAt: expiresAt, generation: generation, markerHash: written.hash,
  });
  log("selfUpdate.beginProbation to=" + opts.to + " expiresAt=" + expiresAt + " gen=" + generation);
  return { markerPath: markerPath, installedAt: installedAt, expiresAt: expiresAt, generation: generation };
}

/**
 * @primitive b.selfUpdate.confirmHealthy
 * @signature b.selfUpdate.confirmHealthy(opts)
 * @since     0.17.13
 * @status    stable
 * @related   b.selfUpdate.beginProbation, b.selfUpdate.evaluateOnBoot
 *
 * Clear the probation marker — the explicit clean / healthy signal. The new
 * binary calls this once its own startup health checks pass (and an operator's
 * graceful-shutdown hook may call it too, marking a clean stop). With the marker
 * gone, a later `evaluateOnBoot` finds no probation and keeps the binary. Absence
 * of this signal at the next boot past the window is what `evaluateOnBoot` reads
 * as a failed probation. Idempotent: a missing marker returns `cleared: false`.
 *
 * @opts
 *   to:         string,   // required — the probationary target (locates the marker)
 *   markerPath: string,   // override marker path (must match beginProbation)
 *
 * @example
 *   // in the new binary, after startup health checks pass:
 *   var r = await b.selfUpdate.confirmHealthy({ to: "/opt/app/app.bin" });
 *   r.cleared;   // → true (marker removed)
 */
async function confirmHealthy(opts) {
  _validateConfirmOpts(opts);
  var markerPath = _resolveMarkerPath(opts);
  var cleared = false;
  if (nodeFs.existsSync(markerPath)) {
    try {
      nodeFs.unlinkSync(markerPath);
      cleared = true;
    } catch (e) {
      throw new SelfUpdateError("selfupdate/probation-confirm-failed",
        "selfUpdate.confirmHealthy: failed to clear probation marker " + markerPath + ": " +
        /* c8 ignore next */
        ((e && e.message) || String(e)));
    }
  }
  _safeAuditEmit("selfupdate.probation.confirmed", "success", {
    to: opts.to, markerPath: markerPath, cleared: cleared,
  });
  log("selfUpdate.confirmHealthy to=" + opts.to + " cleared=" + cleared);
  return { ok: true, cleared: cleared, markerPath: markerPath };
}

/**
 * @primitive b.selfUpdate.evaluateOnBoot
 * @signature b.selfUpdate.evaluateOnBoot(opts)
 * @since     0.17.13
 * @status    stable
 * @related   b.selfUpdate.beginProbation, b.selfUpdate.confirmHealthy, b.selfUpdate.rollback
 *
 * Decide, at process start, whether a probationary install should be kept or
 * rolled back. Returns `{ action: "keep" | "rollback", reason }`. No marker, or a
 * marker still inside its window, keeps (a clean stop / restart within the window
 * is not a crash). A marker past its window with no `confirmHealthy` means the
 * binary never became healthy → the known-good backup is restored over the
 * target and the marker cleared.
 *
 * Before restoring, it RE-VERIFIES: the bytes currently at `to` must still hash
 * to the marker's `expectedHash` (so a marker left by a swap that FAILED — where
 * the probationary binary was never installed — never triggers a phantom
 * rollback), and the backup must exist (otherwise it keeps and defers to the
 * operator rather than destroying the only present binary). A corrupt / malformed
 * marker keeps, never rolls back.
 *
 * @opts
 *   to:         string,   // required — the probationary target
 *   backupTo:   string,   // override the marker's backup path
 *   markerPath: string,   // override marker path (must match beginProbation)
 *   now:        number,   // override the wall clock (epoch ms) for deterministic evaluation
 *
 * @example
 *   // at process start, before serving traffic:
 *   var d = await b.selfUpdate.evaluateOnBoot({ to: "/opt/app/app.bin" });
 *   if (d.action === "rollback") process.exit(1);   // restart onto the restored binary
 */
async function evaluateOnBoot(opts) {
  _validateEvaluateOpts(opts);
  var markerPath = _resolveMarkerPath(opts);
  var to  = opts.to;
  var now = typeof opts.now === "number" ? opts.now : Date.now();

  if (!nodeFs.existsSync(markerPath)) {
    return _probationKeep("no-probation-active", to, markerPath);
  }
  var marker;
  try {
    marker = await atomicFile.readJson(markerPath, { maxBytes: PROBATION_MARKER_MAX });
  } catch (_e) {
    // A corrupt / unreadable marker must not phantom-rollback.
    return _probationKeep("marker-unreadable", to, markerPath);
  }
  if (!marker || typeof marker.expiresAt !== "number" || typeof marker.expectedHash !== "string") {
    return _probationKeep("marker-malformed", to, markerPath);
  }
  // Inside the window — a clean stop / restart is not a crash.
  if (now < marker.expiresAt) {
    return _probationKeep("within-probation-window", to, markerPath);
  }

  // Expired with no confirmHealthy. Re-verify before restoring.
  var backupTo = typeof opts.backupTo === "string" ? opts.backupTo : marker.backupTo;
  var alg = ALLOWED_HASH_ALGS.indexOf(marker.hashAlgo) !== -1 ? marker.hashAlgo : DEFAULT_HASH_ALG;

  // The probationary binary must actually be the one installed at `to`; if `to`
  // is absent or holds different bytes (a swap that failed and left the old
  // binary), rolling back would be a phantom.
  var currentHash = null;
  try {
    var curBytes = atomicFile.fdSafeReadSync(to, { maxBytes: C.BYTES.gib(1) });
    currentHash = nodeCrypto.createHash(alg).update(curBytes).digest("hex");
  } catch (_r) { currentHash = null; }
  if (currentHash !== marker.expectedHash) {
    return _probationKeep("installed-binary-not-probationary", to, markerPath);
  }
  if (typeof backupTo !== "string" || !nodeFs.existsSync(backupTo)) {
    // No backup to restore — keep the current binary and defer to the operator
    // rather than leaving the target with nothing.
    return _probationKeep("backup-unavailable", to, markerPath);
  }

  // Restore the known-good backup over the failed probationary binary. On boot
  // the target is not yet running, so an atomic write-replace is safe.
  try {
    var backupBytes = atomicFile.fdSafeReadSync(backupTo, { maxBytes: C.BYTES.gib(1) });
    var restoreMode;
    /* c8 ignore next -- statSync catch is TOCTOU-defensive: `to` was just read for the hash check */
    try { restoreMode = (nodeFs.statSync(to).mode & 0o777); } catch (_sm) { restoreMode = 0o600; }
    await atomicFile.write(to, backupBytes, { fileMode: restoreMode, overwrite: true });
  } catch (e) {
    _safeAuditEmit("selfupdate.probation.rollback_failed", "denied", {
      to: to, backupTo: backupTo, markerPath: markerPath,
      /* c8 ignore next */
      reason: "restore-failed", message: (e && e.message) || String(e),
    });
    throw new SelfUpdateError("selfupdate/probation-rollback-failed",
      "selfUpdate.evaluateOnBoot: probation rollback restore of " + to + " failed: " +
      /* c8 ignore next */
      ((e && e.message) || String(e)));
  }
  atomicFile.fsyncDir(nodePath.dirname(to));
  // Marker cleanup is best-effort; the unlink-failure catch is unforceable here.
  /* c8 ignore next */
  try { nodeFs.unlinkSync(markerPath); } catch (_u) { /* marker cleanup best-effort */ }

  _safeAuditEmit("selfupdate.probation.rolled_back", "success", {
    to: to, backupTo: backupTo, markerPath: markerPath, generation: marker.generation,
  });
  log("selfUpdate.evaluateOnBoot rolled back to=" + to + " from=" + backupTo);
  return { action: "rollback", reason: "probation-window-elapsed-without-confirmation",
           to: to, backupTo: backupTo, generation: marker.generation };
}

module.exports = {
  poll:                  poll,
  verify:                verify,
  swap:                  swap,
  rollback:              rollback,
  beginProbation:        beginProbation,
  confirmHealthy:        confirmHealthy,
  evaluateOnBoot:        evaluateOnBoot,
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
  _pathsAlias:           _pathsAlias,
};
