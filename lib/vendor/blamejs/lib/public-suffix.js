// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *     - RFC 9989 (DMARC) replaces RFC 7489's heuristic
 *       organizational-domain derivation with a PSL lookup, including
 *       the `psd=` (public-suffix-domain policy) and `np=`
 *       (non-public-suffix policy) tags
 *     - BIMI (draft-blank-ietf-bimi) uses the same organizational-domain
 *       logic to scope brand indicators
 *     - Same-site cookie scoping (RFC 6265bis) refers to the PSL when
 *       deciding whether `Domain=co.uk` is a "public suffix" attempt
 *
 *   This module ships the PSL as a vendored data file
 *   (`lib/vendor/public-suffix-list.dat`) and parses it once at
 *   module-load. The algorithm is the canonical one published at
 *   https://publicsuffix.org/list/: an exception rule outranks every
 *   other match, and otherwise the matching rule with the MOST LABELS
 *   prevails whether it is exact or a wildcard. Ranking by kind instead
 *   would hand `x.kawasaki.jp` to `jp` rather than to
 *   `*.kawasaki.jp`.
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

// The index of the first character that cannot appear in a host name, or -1.
//
// Control / NUL / whitespace bytes, DEL, and the URL-structural delimiters
// domainToASCII silently TRUNCATES at — "/" (0x2F), "?" (0x3F), "#" (0x23),
// "\" (0x5C) reduce "example.com/evil" to "example.com" rather than failing,
// which would let a hostile host masquerade as a trusted prefix. ":" / "@" /
// "[" / "]" already make domainToASCII return "", but they are rejected here
// too so every non-host character fails closed rather than silently.
//
// Exported because it is the framework's definition of "a character that may
// appear in a host", and the DNS wire encoder needs the same answer. When it
// had its own — a shorter one — `b.network.dns` encoded `a\u0000.com` and
// `example.com/evil` into query labels that this module refuses outright.
function _firstNonHostCharacter(name) {
  for (var i = 0; i < name.length; i += 1) {
    var cp = name.charCodeAt(i);
    if (cp < 0x21 || cp === 0x7f ||
        cp === 0x2f || cp === 0x3f || cp === 0x23 || cp === 0x5c ||   // / ? # \
        cp === 0x3a || cp === 0x40 || cp === 0x5b || cp === 0x5d) {   // : @ [ ]
      return i;
    }
  }
  return -1;
}

// The characters UTS #46 treats as a label separator, and therefore the ones
// that can mark the root of an absolute name. Scanned against Node's own
// mapping and found to be exactly this set across the BMP and the SMP.
function _isRootMarker(ch) {
  return ch === "." || ch === "。" || ch === "．" || ch === "｡";
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
  // Strip a single trailing root marker (FQDN form) BEFORE measuring. The
  // absolute and relative spellings of one name encode to identical wire
  // bytes, so measuring the marker would refuse a maximum-length name written
  // absolutely while accepting it written relatively.
  //
  // Which character marks the root is not fixed: UTS #46 maps U+3002, U+FF0E
  // and U+FF61 to "." as well, so `münchen.example。` is absolute too.
  // Recognising all four here rather than only the ASCII dot is what lets the
  // `rootStripped` guard below hold — exactly one marker comes off in total,
  // and a second is an empty final label rather than something to remove.
  //
  // A marker that only APPEARS during conversion — because an IDNA-ignored
  // code point trailed it — is handled by the post-conversion strip below,
  // which the same guard keeps mutually exclusive with this one.
  var s = domain.toLowerCase();
  var rootStripped = false;
  if (_isRootMarker(s.charAt(s.length - 1))) {
    s = s.slice(0, -1);
    rootStripped = true;
    if (s.length === 0) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain must not be a bare dot");
    }
  }
  if (s.length > 253) {
    // A cheap bound on the INPUT, so a pathological string is refused before
    // conversion. It is not the authoritative check: an internationalized name
    // grows when it becomes A-labels, so the real test is on the converted form
    // below. Every ASCII name is settled here, since conversion leaves it as-is.
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain exceeds 253-octet RFC 1035 limit");
  }
  if (_firstNonHostCharacter(s) !== -1) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains a control byte or URL delimiter");
  }
  // IDN-normalize — non-ASCII labels become xn--… via Node's UTS #46
  // implementation. Empty string back means the input was malformed
  // beyond what UTS #46 will accept (e.g. starts with U+FFFD).
  var ascii = nodeUrl.domainToASCII(s);
  if (!ascii) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain failed IDN normalization");
  }
  // No empty labels (`foo..bar`) and no leading dot. This runs BEFORE the
  // root-marker strip below, so a name carrying an empty final label cannot be
  // turned into a valid one by removing a dot: `münchen.example。。` converts to
  // a trailing `..` and is refused here rather than quietly becoming a
  // different, real domain.
  if (ascii.indexOf("..") !== -1 || ascii.charCodeAt(0) === 46) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains empty label");
  }
  // RFC 1035 §2.3.4 — 253 octets max for the wire form (255 minus the leading
  // length byte and the root's null). This is the AUTHORITATIVE check, and it
  // has to run on the converted name: an internationalized label grows into its
  // `xn--` form, so five 44-character labels are 224 characters going in and
  // 254 octets coming out, with every individual label a legal 50. Measuring
  // the input handed the caller a name that cannot be put on the wire, and a
  // caller cannot tell — it looks like any other domain, and the DMARC walk
  // stepped over the unqueryable target and applied an ancestor's policy.
  //
  // A trailing root marker is still present at this point and does not count:
  // the wire form carries the root as a zero-length label, not a character.
  var withoutRoot = ascii.charCodeAt(ascii.length - 1) === 46
    ? ascii.length - 1 : ascii.length;
  if (withoutRoot > 253) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain exceeds 253-octet RFC 1035 limit once converted " +
      "to A-labels (" + withoutRoot + " octets)");
  }
  // The root marker is stripped here when it was not an ASCII dot on the way
  // in. UTS #46 maps U+3002, U+FF0E and U+FF61 to ".", so `münchen.example。`
  // arrives with no trailing dot and leaves the conversion with one. Returning
  // that from a function whose contract is to strip the trailing dot leaves
  // every caller to compensate, and the ones that do not compare two spellings
  // of the same absolute name as different names.
  //
  // At most ONE root marker is removed in total. A dot still here after one was
  // already taken off means the name ended in two of them — an empty final
  // label — and stripping the second would hand the caller a different, valid
  // domain than the one they asked about.
  if (ascii.charCodeAt(ascii.length - 1) === 46 /* "." */) {
    if (rootStripped) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain contains empty label");
    }
    ascii = ascii.slice(0, -1);
    if (ascii.length === 0) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain must not be a bare dot");
    }
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
  // An exception rule outranks everything. Among the rest the
  // prevailing rule is the one with the MOST LABELS, whatever its
  // kind — not exact-before-wildcard, which is a different order
  // entirely and the wrong one. `*.kawasaki.jp` has three labels and
  // `jp` has one, so a name under that registry takes the wildcard;
  // ranking by kind handed it to `jp` and merged every tenant of the
  // registry into one organizational domain. 275 of the list's 283
  // wildcards sit under a listed TLD and were resolved that way.
  // We collect the longest candidate per rule kind and compare at the
  // end.
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
  if (exactMatch !== null && wildcardMatch !== null) {
    // Both kinds matched — the longer rule prevails. A wildcard's suffix
    // carries the label it consumed, so counting labels on the resulting
    // suffixes compares the rules that produced them.
    return wildcardMatch.split(".").length > exactMatch.split(".").length
      ? wildcardMatch
      : exactMatch;
  }
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
 * Mozilla PSL algorithm (https://publicsuffix.org/list/). An exception
 * rule outranks every other match; otherwise the matching rule with
 * the most labels prevails, whether it is exact or a wildcard, and the
 * implicit "*" rule applies when nothing matches. So `x.kawasaki.jp`
 * resolves to itself under `*.kawasaki.jp` rather than to `jp`. Input
 * is lowercased and IDN-normalized (punycode) before lookup. Returns
 * `null` for inputs that have no registrable parent (single-label
 * TLDs, public-suffix-only inputs).
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

/**
 * @primitive b.publicSuffix.canonicalDomain
 * @signature b.publicSuffix.canonicalDomain(domain)
 * @since     0.15.50
 * @status    stable
 * @related   b.publicSuffix.organizationalDomain, b.publicSuffix.publicSuffix
 *
 * Returns the bare canonical host form of `domain` for identity
 * comparison: lowercase, a single trailing dot stripped, and IDN
 * labels normalized to their A-label (punycode) form. Unlike
 * `organizationalDomain` it does NOT walk the public-suffix list — it
 * returns the input host itself in canonical form.
 *
 * Two values that denote the same host in different encodings (case,
 * trailing dot, U-label vs A-label) return the SAME string, so an
 * equality compare is encoding-stable — the building block for DMARC
 * alignment and certificate SAN-vs-domain authorization checks, where
 * one side normalizing differently from the other is a bypass.
 *
 * Non-throwing: returns `""` for any input that is not a valid host
 * (control bytes, empty labels, over the 253-octet limit), so a
 * hostile or garbage value canonicalizes to `""` and matches nothing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.canonicalDomain("Example.COM.");   // → "example.com"
 *   b.publicSuffix.canonicalDomain("a..b");             // → ""
 */
function canonicalDomain(domain) {
  try { return _normalizeInput(domain); } catch (_e) { return ""; }
}

module.exports = {
  publicSuffix:         publicSuffix,
  organizationalDomain: organizationalDomain,
  canonicalDomain:      canonicalDomain,
  isPublicSuffix:       isPublicSuffix,
  lookupSource:         lookupSource,
  _firstNonHostCharacter: _firstNonHostCharacter,
  // Exported for the same reason as the character predicate above: this is the
  // framework's answer to "which characters mark the root of an absolute name",
  // and a second copy of the set drifts from it.
  _isRootMarker:          _isRootMarker,
};
