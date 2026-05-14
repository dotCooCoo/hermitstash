"use strict";
/**
 * @module     b.publicSuffix
 * @nav        Validation
 * @title      Public Suffix
 * @order      140
 * @card       Mozilla Public Suffix List substrate — exposes
 *             `b.publicSuffix.publicSuffix(domain)` /
 *             `b.publicSuffix.organizationalDomain(domain)` /
 *             `b.publicSuffix.isPublicSuffix(domain)` for the
 *             "registrable domain" derivation that DMARCbis,
 *             BIMI, cookie-scope, and same-site policies all need.
 *
 * @intro
 *   The Public Suffix List (PSL) is Mozilla's published catalog of
 *   "effective top-level domains" — labels under which independent
 *   parties can register names (`com`, `co.uk`, `s3.amazonaws.com`,
 *   …). It is the canonical reference for deriving the
 *   "organizational domain" of a hostname: the registrable label one
 *   level below its public suffix. Several upstream specs lean on it
 *   directly:
 *
 *     - DMARCbis (IETF DMARC WG) replaces RFC 7489's heuristic
 *       organizational-domain derivation with a PSL lookup, including
 *       new `psd=` (public-suffix-domain policy) and `np=`
 *       (non-public-suffix policy) tags
 *     - BIMI (RFC 9669 + draft) uses the same organizational-domain
 *       logic to scope brand indicators
 *     - Same-site cookie scoping (RFC 6265bis) refers to the PSL when
 *       deciding whether `Domain=co.uk` is a "public suffix" attempt
 *
 *   This module ships the PSL as a vendored data file
 *   (`lib/vendor/public-suffix-list.dat`) and parses it once at
 *   module-load. The algorithm is the canonical one published at
 *   https://publicsuffix.org/list/ (exact > exception > wildcard).
 *
 *   Surface:
 *
 *     b.publicSuffix.publicSuffix("example.co.uk")
 *       // → "co.uk"
 *
 *     b.publicSuffix.organizationalDomain("foo.bar.example.co.uk")
 *       // → "example.co.uk"
 *
 *     b.publicSuffix.isPublicSuffix("co.uk")
 *       // → true
 *
 *     b.publicSuffix.lookupSource()
 *       // → { vendoredAt: "2026-05-09", entries: <n>, sha256: "..." }
 *
 *   IDN inputs are punycode-normalized via Node's `url.domainToASCII`
 *   before lookup. Bad inputs throw `PublicSuffixError`.
 */

var nodeUrl  = require("node:url");
var vendorData = require("./vendor-data");
var pslDataModule = require("./vendor/public-suffix-list.data");
var { PublicSuffixError } = require("./framework-error");

// Vendored PSL data file. Loaded via b.vendorData which inlines the
// bytes as a CommonJS module, dual-hash + SLH-DSA-SHAKE-256f-signature
// verifies on first access, and carries an in-payload canary the
// PSL parser must observe. Packaging-mode-invariant — survives SEA,
// pkg, nexe, esbuild bundles, Lambda layers, Bun/Deno compile. See
// lib/vendor-data.js for the integrity surface.

function _err(code, message) {
  return new PublicSuffixError(code, message);
}

// _normalizeInput — lowercase + IDN-normalize a candidate domain.
// Returns a plain ASCII (punycode) string with no leading/trailing
// dots and no empty labels. Throws PublicSuffixError on bad shape so
// callers see a single error class for every reject path.
function _normalizeInput(domain) {
  if (typeof domain !== "string") {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain must be a string");
  }
  if (domain.length === 0) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain must not be empty");
  }
  if (domain.length > 253) {
    // RFC 1035 §2.3.4 — 253 octets max for the wire form (255 minus
    // length-byte + null). Anything longer is structurally invalid.
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain exceeds 253-octet RFC 1035 limit");
  }
  // Strip a single trailing dot (FQDN form). Multiple trailing dots,
  // leading dots, or embedded empty labels remain rejected below.
  var s = domain.toLowerCase();
  if (s.charCodeAt(s.length - 1) === 46 /* "." */) {
    s = s.slice(0, -1);
    if (s.length === 0) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain must not be a bare dot");
    }
  }
  // Reject control / null / whitespace bytes outright. domainToASCII
  // would silently rewrite some of them; we want hostile inputs to
  // throw, not be coerced.
  for (var i = 0; i < s.length; i += 1) {
    var cp = s.charCodeAt(i);
    if (cp < 0x21 || cp === 0x7f) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain contains control / whitespace byte");
    }
  }
  // IDN-normalize — non-ASCII labels become xn--… via Node's UTS #46
  // implementation. Empty string back means the input was malformed
  // beyond what UTS #46 will accept (e.g. starts with U+FFFD).
  var ascii = nodeUrl.domainToASCII(s);
  if (!ascii) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain failed IDN normalization");
  }
  // No empty labels (`foo..bar`) and no leading dot.
  if (ascii.indexOf("..") !== -1 || ascii.charCodeAt(0) === 46) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains empty label");
  }
  return ascii;
}

// _parsePsl — walk the vendored .dat file once at load and produce
// the lookup tables. The .dat format is:
//   - blank lines: skip
//   - lines starting with "//": comment / section marker
//   - "*.suffix": wildcard rule (matches one extra label)
//   - "!suffix":  exception rule (suppresses a parent wildcard)
//   - "suffix":   exact rule
//
// Non-ASCII rule labels are punycode-encoded so they match
// IDN-normalized input directly. The original PSL file already
// contains them in punycode form; we still canonicalize defensively
// in case a future revision changes shape.
function _parsePsl(text) {
  var exact     = Object.create(null); // suffix -> true
  var wildcard  = Object.create(null); // parent  -> true (e.g. "ck" for "*.ck")
  var exception = Object.create(null); // suffix -> true (full e.g. "www.ck")
  var lines = text.split(/\r?\n/);
  var entries = 0;

  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (!line) continue;
    // A space within a line is the start of an inline comment /
    // metadata note (Mozilla's convention); take the leading token.
    var sp = line.indexOf(" ");
    if (sp !== -1) line = line.slice(0, sp);
    if (!line) continue;
    if (line.charCodeAt(0) === 47 /* "/" */ &&
        line.charCodeAt(1) === 47) continue;

    var rule = line.toLowerCase();
    // IDN-normalize each rule. domainToASCII returns "" on failure;
    // we skip rather than throw — the PSL is curated and any
    // failure here means a future format change rather than hostile
    // input from a caller.
    var asciiRule = nodeUrl.domainToASCII(rule);
    if (!asciiRule) continue;

    if (asciiRule.charCodeAt(0) === 33 /* "!" */) {
      exception[asciiRule.slice(1)] = true;
    } else if (asciiRule.charCodeAt(0) === 42 /* "*" */ &&
               asciiRule.charCodeAt(1) === 46 /* "." */) {
      wildcard[asciiRule.slice(2)] = true;
    } else {
      exact[asciiRule] = true;
    }
    entries += 1;
  }

  return { exact: exact, wildcard: wildcard, exception: exception, entries: entries };
}

// Initialize once at module load. Operators with a missing or
// unreadable vendored file see a clear startup-time failure ("config-
// time" tier — throw rather than silently fall back to a permissive
// default that would let phishing-shaped hosts past).
var _data;
var _sourceMeta;
(function _init() {
  var raw;
  try {
    raw = vendorData.get("public-suffix-list");
  } catch (e) {
    throw _err("public-suffix/not-loaded",
      "publicSuffix: vendored PSL data not loadable via b.vendorData " +
      "(" + (e && e.message ? e.message : "unknown error") + ")");
  }
  var parsed = _parsePsl(raw.toString("utf8"));
  _data = parsed;
  // Provenance comes from the .data.js module's own metadata, which
  // carries sha256 + sha3-512 + signing public-key fingerprint +
  // upstream fetchedAt timestamp. All four were verified by
  // vendorData.get() before the bytes reached this caller.
  var meta = pslDataModule.metadata;
  _sourceMeta = Object.freeze({
    vendoredAt: meta.fetchedAt,
    entries: parsed.entries,
    sha256: meta.sha256,
    signedBy: meta.publicKeyFingerprint,
  });
})();

// _lookupAscii — core algorithm against the parsed tables. Operates
// on a normalized ASCII domain. Returns the longest matching public
// suffix, or null if no rule matches and the implicit-* rule produces
// a shorter result than the input (which only happens for single-
// label inputs — those have no public suffix per the algorithm).
function _lookupAscii(ascii) {
  var labels = ascii.split(".");

  // Walk longest-to-shortest. Per Mozilla's algorithm:
  //   1. If an exception rule "!a.b.c" matches the input, the public
  //      suffix is the parent of the matched rule (one label dropped).
  //   2. Else if an exact rule matches, that's the suffix.
  //   3. Else if a wildcard rule "*.b.c" matches (input ends in
  //      ".b.c" with at least one extra label), the suffix is one
  //      label deeper than the wildcard's parent.
  //   4. Else the implicit "*" rule applies: suffix = the rightmost
  //      label.
  //
  // Exception > exact > wildcard. We collect candidates per rule
  // type and pick the precedence order at the end.
  var exceptionMatch = null;
  var exactMatch     = null;
  var wildcardMatch  = null;

  for (var i = 0; i < labels.length; i += 1) {
    var candidate = labels.slice(i).join(".");
    if (_data.exception[candidate]) {
      // Exception rule's "public suffix" is the candidate with its
      // leftmost label removed (the rule overrides a parent wildcard
      // by saying "this exact name is registrable, suffix is below").
      var parentLabels = labels.slice(i + 1);
      if (parentLabels.length > 0) {
        exceptionMatch = parentLabels.join(".");
      } else {
        exceptionMatch = "";
      }
      break;
    }
    if (!exactMatch && _data.exact[candidate]) {
      exactMatch = candidate;
    }
    if (!wildcardMatch && i > 0) {
      // For "*.b.c" to match input "a.b.c": the wildcard rule keys
      // off the parent ("b.c"). We're at label-index i; the parent
      // suffix is labels[i..]. The wildcard table indexes by parent,
      // so a hit at "b.c" means input "a.b.c" matches the rule
      // "*.b.c", and the public suffix is labels[i-1..] (one extra
      // label included).
      if (_data.wildcard[candidate]) {
        wildcardMatch = labels.slice(i - 1).join(".");
      }
    }
  }

  if (exceptionMatch !== null) return exceptionMatch === "" ? null : exceptionMatch;
  if (exactMatch    !== null) return exactMatch;
  if (wildcardMatch !== null) return wildcardMatch;
  // Implicit "*" rule — every TLD is its own public suffix even when
  // the PSL doesn't list it. For a multi-label input, the suffix is
  // the rightmost label. For a single-label input, there is no
  // registrable parent (the input IS a TLD), return null so callers
  // distinguish "is a public suffix" from "has a public suffix".
  if (labels.length >= 2) return labels[labels.length - 1];
  return null;
}

/**
 * @primitive b.publicSuffix.publicSuffix
 * @signature b.publicSuffix.publicSuffix(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.organizationalDomain, b.publicSuffix.isPublicSuffix
 *
 * Returns the longest matching public suffix for `domain`, per the
 * Mozilla PSL algorithm (https://publicsuffix.org/list/). Exception
 * rules outrank exact rules, exact rules outrank wildcards, wildcards
 * outrank the implicit "*" rule. Input is lowercased and IDN-
 * normalized (punycode) before lookup. Returns `null` for inputs that
 * have no registrable parent (single-label TLDs, public-suffix-only
 * inputs).
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) for
 * non-string / empty / overlong / control-byte-bearing inputs.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.publicSuffix("example.co.uk");
 *   // → "co.uk"
 *   b.publicSuffix.publicSuffix("foo.bar.example.com");
 *   // → "com"
 */
function publicSuffix(domain) {
  var ascii = _normalizeInput(domain);
  return _lookupAscii(ascii);
}

/**
 * @primitive b.publicSuffix.organizationalDomain
 * @signature b.publicSuffix.organizationalDomain(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix, b.publicSuffix.isPublicSuffix
 *
 * Returns the registrable "organizational domain" — the public
 * suffix plus exactly one label to its left. This is the value
 * DMARCbis, BIMI, and cookie-scope policies operate on when they
 * decide whether two hostnames belong to the same registered party.
 *
 * Returns `null` when `domain` IS a public suffix (no organizational
 * parent exists — `co.uk` has no registrable owner, only the labels
 * registered under it do).
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) on bad
 * input shape.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.organizationalDomain("foo.bar.example.co.uk");
 *   // → "example.co.uk"
 *   b.publicSuffix.organizationalDomain("example.com");
 *   // → "example.com"
 *   b.publicSuffix.organizationalDomain("co.uk");
 *   // → null
 */
function organizationalDomain(domain) {
  var ascii = _normalizeInput(domain);
  var suffix = _lookupAscii(ascii);
  if (suffix === null) return null;
  if (suffix === ascii) return null; // input IS a public suffix
  // Walk back one label from the suffix. ascii ends in "." + suffix
  // by construction (exact / wildcard / implicit-* all guarantee it).
  var suffixLabels = suffix.split(".").length;
  var labels = ascii.split(".");
  if (labels.length <= suffixLabels) return null;
  return labels.slice(labels.length - suffixLabels - 1).join(".");
}

/**
 * @primitive b.publicSuffix.isPublicSuffix
 * @signature b.publicSuffix.isPublicSuffix(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix, b.publicSuffix.organizationalDomain
 *
 * Returns `true` when `domain` is itself a public suffix (e.g.
 * `"co.uk"`, `"com"`, `"s3.amazonaws.com"`), `false` otherwise.
 * DMARCbis uses this distinction for its `psd=` (public-suffix-
 * domain) policy: a TLD operator publishing a record on `co.uk`
 * itself is a different actor than `example.co.uk` publishing one.
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) on bad
 * input shape.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.isPublicSuffix("co.uk");
 *   // → true
 *   b.publicSuffix.isPublicSuffix("example.co.uk");
 *   // → false
 */
function isPublicSuffix(domain) {
  var ascii = _normalizeInput(domain);
  var suffix = _lookupAscii(ascii);
  return suffix !== null && suffix === ascii;
}

/**
 * @primitive b.publicSuffix.lookupSource
 * @signature b.publicSuffix.lookupSource()
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix
 *
 * Returns transparency metadata for the loaded PSL: the date the
 * file was vendored (`vendoredAt`, ISO 8601 from
 * `lib/vendor/MANIFEST.json`), the parsed-rule count (`entries`),
 * and the SHA-256 hash of the raw file contents (`sha256`, hex). Use
 * to surface in operator dashboards / forensic logs so a snapshot of
 * the PSL the framework was making decisions against is reproducible
 * after the fact.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var src = b.publicSuffix.lookupSource();
 *   // → { vendoredAt: "2026-05-09", entries: 9000, sha256: "a008..." }
 */
function lookupSource() {
  return _sourceMeta;
}

module.exports = {
  publicSuffix:         publicSuffix,
  organizationalDomain: organizationalDomain,
  isPublicSuffix:       isPublicSuffix,
  lookupSource:         lookupSource,
};
