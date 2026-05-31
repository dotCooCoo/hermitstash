"use strict";
/**
 * @module     b.guardListUnsubscribe
 * @nav        Guards
 * @title      Guard List-Unsubscribe
 * @order      465
 *
 * @intro
 *   RFC 2369 `List-Unsubscribe` + RFC 8058 one-click
 *   `List-Unsubscribe-Post` header validator. Gates the outbound
 *   submission path's marketing / transactional mail so messages
 *   carrying a `List-Id` (or any mailing-list shape) emit headers
 *   that Gmail / Yahoo / Outlook one-click unsubscribe machinery
 *   actually accepts.
 *
 *   ## Why this primitive vs. inline header construction
 *
 *   Gmail's bulk-sender requirements (effective 2024-02) and Yahoo's
 *   matching policy refuse mail that doesn't carry the RFC 8058 pair
 *   correctly. Operators get senders rate-limited or buckets-dropped
 *   when the headers are malformed. Common pitfalls this primitive
 *   refuses:
 *
 *     - **No HTTPS URI** — Gmail+Yahoo require at least one
 *       `https://` URI in the `List-Unsubscribe` header. `mailto:`
 *       alone is no longer sufficient post-2024.
 *     - **`http://` instead of `https://`** — refused; one-click
 *       endpoint MUST be TLS.
 *     - **`javascript:` / `data:` / `file:` schemes** — always
 *       refused regardless of context.
 *     - **`List-Unsubscribe-Post: List-Unsubscribe=One-Click`** —
 *       MUST be EXACTLY this token. Operator-supplied variants
 *       (`OneClick`, `one-click`, lowercased `=` value) refused.
 *     - **HTTPS URI without paired `List-Unsubscribe-Post`** — the
 *       Post header opts the endpoint into one-click. Without it,
 *       Gmail's UI treats the HTTPS URI as a regular link (operator
 *       loses the inbox-list "Unsubscribe" button).
 *
 *   ## Verdict shape
 *
 *   ```js
 *   {
 *     action:        "accept" | "refuse",
 *     reason:        string,
 *     uris:          [{ scheme, raw, oneClickEligible }, ...],
 *     hasHttpsUri:   bool,
 *     hasMailtoUri:  bool,
 *     postHeaderOk:  bool,
 *     oneClickReady: bool,
 *   }
 *   ```
 *
 *   Under `strict` (default for HIPAA / PCI / GDPR / SOC2 mailings
 *   that need bulk-sender compliance), `oneClickReady: false` →
 *   `action: "refuse"`. Under `balanced`, the primitive returns the
 *   verdict but always accepts — operator's outbound pipeline makes
 *   the policy decision downstream.
 *
 *   ## CVE / threat model
 *
 *   - **Unsubscribe-link injection** — operator's template-rendered
 *     `List-Unsubscribe` could be tampered through prompt-injection
 *     into an AI-generated newsletter. CRLF refused (header
 *     injection); `javascript:` / `data:` / `file:` refused (XSS via
 *     mail-client rendering); URL length cap (default 2048).
 *   - **Open-redirect via List-Unsubscribe** — operator validates the
 *     HTTPS URI's target host with their own `safeRedirect` /
 *     `safeUrl` allowlist downstream; this guard checks the SHAPE,
 *     not the operator's target-host policy.
 *   - **Email client mishandling** (Outlook's history of fetching
 *     `mailto:` automatically) — the primitive doesn't render the
 *     header; consumers using it inside `b.guardEmail.validateMessage`
 *     get layered defense.
 *
 * @card
 *   RFC 2369 + RFC 8058 List-Unsubscribe / List-Unsubscribe-Post validator. Refuses non-HTTPS one-click URIs, javascript:/data:/file: schemes, missing Post header, malformed Post token. Gmail+Yahoo bulk-sender compliance defense.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var safeUrl            = require("./safe-url");

var GuardListUnsubscribeError = defineClass("GuardListUnsubscribeError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxBytes:           C.BYTES.kib(4),
    maxUris:            4,                                                                               // URI-count cap
    maxUriBytes:        2048,                                                                            // per-URI byte cap
    requireHttpsUri:    true,
    requirePostHeader:  true,
    refuseHttp:         true,
  },
  balanced: {
    maxBytes:           C.BYTES.kib(4),
    maxUris:            8,                                                                               // URI-count cap
    maxUriBytes:        2048,                                                                            // per-URI byte cap
    requireHttpsUri:    false,
    requirePostHeader:  false,
    refuseHttp:         true,
  },
  permissive: {
    maxBytes:           C.BYTES.kib(8),
    maxUris:            16,                                                                              // URI-count cap
    maxUriBytes:        4096,                                                                            // per-URI byte cap
    requireHttpsUri:    false,
    requirePostHeader:  false,
    refuseHttp:         false,
  },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// RFC 8058 §2: Post header value MUST be exactly
// `List-Unsubscribe=One-Click`. Token is case-sensitive per Gmail /
// Yahoo bulk-sender enforcement (mixed-case variants silently fail
// one-click on Gmail).
var ONE_CLICK_POST_VALUE = "List-Unsubscribe=One-Click";

// Always-refused schemes regardless of profile (XSS / mail-client
// rendering / local-file-read class).
var DANGEROUS_SCHEMES = Object.freeze({
  "javascript:": true,
  "data:":       true,
  "file:":       true,
  "vbscript:":   true,
  "blob:":       true,
});

// IP-literal + reserved-hostname refusal for HTTPS one-click URIs.
// One-click receivers POST to the URI without further operator gate;
// an attacker-supplied List-Unsubscribe URI pointing at `127.0.0.1`
// / `169.254.169.254` (cloud metadata) / `[::1]` / `localhost` lets
// the mailbox provider's auto-fetcher target the operator's own
// infrastructure — classic SSRF. The check is wholly host-name-shape
// based (no DNS resolution); DNS-rebinding defense is left to the
// fetcher (which should pin the IP across resolution + request).
var IPV4_LITERAL_RE = /^\d+\.\d+\.\d+\.\d+$/;                                                            // allow:regex-no-length-cap — anchored shape, hostname length bounded by URL parser
var IPV6_LITERAL_RE = /^\[[0-9A-Fa-f:.]+\]$/;                                                            // allow:regex-no-length-cap — anchored shape, hostname length bounded by URL parser
var RESERVED_LOCAL_HOSTS = Object.freeze({
  "localhost":          true,
  "localhost.localdomain": true,
  "ip6-localhost":      true,
  "ip6-loopback":       true,
});

function _isRefusedAutoFetchHost(hostname, allowedHosts) {
  if (typeof hostname !== "string" || hostname.length === 0) return "missing-host";
  // Normalize the trailing root-zone dot BEFORE comparison — RFC 1034
  // §3.1: `foo.` is the absolute form of `foo` (both resolve to the
  // same target). A naive byte-equality check against `localhost`
  // would let an attacker bypass the gate by appending the dot. Same
  // for any reserved-local suffix family. Multiple trailing dots are
  // not valid DNS but we strip them anyway to keep the gate robust
  // against any URL parser that leaves them in `hostname`.
  var lower = hostname.toLowerCase();
  while (lower.length > 0 && lower.charAt(lower.length - 1) === ".") {
    lower = lower.slice(0, -1);
  }
  if (lower.length === 0) return "missing-host";
  if (IPV4_LITERAL_RE.test(lower) || IPV6_LITERAL_RE.test(lower)) return "ip-literal";
  if (RESERVED_LOCAL_HOSTS[lower]) return "reserved-local-host";
  // Hostname suffix refusal — RFC 6761 reserved / mDNS / single-network.
  if (lower === "local" || lower.endsWith(".local")) return "reserved-local-suffix";
  if (lower === "lan" || lower.endsWith(".lan")) return "reserved-local-suffix";
  if (lower === "internal" || lower.endsWith(".internal")) return "reserved-local-suffix";
  // Optional operator allowlist — when supplied, hostname (or any
  // ancestor domain) MUST be present.
  if (Array.isArray(allowedHosts) && allowedHosts.length > 0) {
    var matched = false;
    for (var i = 0; i < allowedHosts.length; i += 1) {
      var allowed = String(allowedHosts[i]).toLowerCase();
      if (lower === allowed || lower.endsWith("." + allowed)) {
        matched = true;
        break;
      }
    }
    if (!matched) return "not-on-allowlist";
  }
  return null;
}

/**
 * @primitive b.guardListUnsubscribe.validate
 * @signature b.guardListUnsubscribe.validate(headers, opts?)
 * @since     0.9.39
 * @status    stable
 * @related   b.guardEmail.validateMessage, b.safeMime.parse
 *
 * Validate the RFC 2369 / RFC 8058 header pair on an outbound
 * marketing or transactional message. Returns the verdict shape;
 * operator's submission listener consults `verdict.action` to
 * accept / refuse the send.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var v = b.guardListUnsubscribe.validate({
 *     listUnsubscribe:      "<mailto:u@x.com?subject=unsub>, <https://x.com/unsub?id=42>",
 *     listUnsubscribePost:  "List-Unsubscribe=One-Click",
 *   });
 *   if (v.action === "refuse") throw new Error(v.reason);
 */
function validate(headers, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  if (!headers || typeof headers !== "object") {
    throw new GuardListUnsubscribeError("guard-list-unsubscribe/bad-input",
      "validate: headers must be a plain object");
  }
  if (typeof headers.listUnsubscribe !== "string" || headers.listUnsubscribe.length === 0) {
    throw new GuardListUnsubscribeError("guard-list-unsubscribe/bad-input",
      "validate: headers.listUnsubscribe must be a non-empty string");
  }
  var raw = headers.listUnsubscribe;
  if (Buffer.byteLength(raw, "utf8") > caps.maxBytes) {
    return _verdict("refuse", "List-Unsubscribe header exceeds maxBytes=" + caps.maxBytes,
      { uris: [], hasHttpsUri: false, hasMailtoUri: false, postHeaderOk: false });
  }
  if (raw.indexOf("\r") !== -1 || raw.indexOf("\n") !== -1) {
    return _verdict("refuse", "header contains CR/LF (RFC 5322 §3.2.5 header-injection refusal)",
      { uris: [], hasHttpsUri: false, hasMailtoUri: false, postHeaderOk: false });
  }
  if (_hasControlChar(raw)) {
    return _verdict("refuse", "header contains NUL / C0 / DEL control char",
      { uris: [], hasHttpsUri: false, hasMailtoUri: false, postHeaderOk: false });
  }

  var uriParts = _extractUris(raw, caps.maxUris);
  if (uriParts === null) {
    return _verdict("refuse", "more than maxUris=" + caps.maxUris + " URIs in List-Unsubscribe",
      { uris: [], hasHttpsUri: false, hasMailtoUri: false, postHeaderOk: false });
  }
  if (uriParts.length === 0) {
    return _verdict("refuse", "List-Unsubscribe has no <URI> elements (RFC 2369 §3.1)",
      { uris: [], hasHttpsUri: false, hasMailtoUri: false, postHeaderOk: false });
  }

  var classified = [];
  var hasHttpsUri  = false;
  var hasMailtoUri = false;
  for (var i = 0; i < uriParts.length; i += 1) {
    var u = uriParts[i];
    // RFC 2369 §3.1 — the URI between `<` and `>` is REQUIRED. An
    // empty `<>` is grammatically invalid + carries no unsubscribe
    // semantics; the earlier shape accepted it and downstream URI-
    // dispatch decisions treated it as a scheme-less URI rather than
    // refusing the whole header.
    if (u.length === 0) {
      return _verdict("refuse", "List-Unsubscribe contains empty `<>` URI (RFC 2369 §3.1)",
        { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
    }
    if (Buffer.byteLength(u, "utf8") > caps.maxUriBytes) {
      return _verdict("refuse", "URI '" + _trunc(u) + "' exceeds maxUriBytes=" + caps.maxUriBytes,
        { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
    }
    var schemeMatch = u.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:)/);                                             // allow:regex-no-length-cap — scheme has fixed-shape repeat cap
    var scheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;
    if (!scheme) {
      return _verdict("refuse", "URI '" + _trunc(u) + "' has no scheme (RFC 3986 §3.1)",
        { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
    }
    if (DANGEROUS_SCHEMES[scheme]) {
      return _verdict("refuse", "URI scheme '" + scheme + "' is on the always-refused list (XSS / file-read class)",
        { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
    }
    if (scheme === "http:" && caps.refuseHttp) {
      return _verdict("refuse", "plain http:// refused in List-Unsubscribe (one-click requires HTTPS per RFC 8058 §2 + Gmail/Yahoo bulk-sender policy)",
        { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
    }
    if (scheme === "https:") {
      var parsed;
      try {
        parsed = safeUrl.parse(u, { allowedProtocols: safeUrl.ALLOW_HTTPS });
      } catch (e) {
        return _verdict("refuse", "HTTPS URI '" + _trunc(u) + "' failed safeUrl parse: " + (e && e.message || String(e)),
          { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
      }
      // SSRF defense — refuse IP-literal hosts, loopback names,
      // reserved-local TLDs, and (when operator supplied
      // `allowedHosts`) anything outside the allowlist. The mailbox
      // provider's auto-fetcher POSTs without our involvement; the
      // header is the only place this can be stopped.
      var refusedHostReason = _isRefusedAutoFetchHost(parsed.hostname, opts.allowedHosts);
      if (refusedHostReason) {
        return _verdict("refuse",
          "HTTPS URI '" + _trunc(u) + "' host '" + parsed.hostname +
          "' refused (" + refusedHostReason + "; auto-fetch SSRF defense)",
          { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
      }
      hasHttpsUri = true;
    } else if (scheme === "mailto:") {
      hasMailtoUri = true;
    }
    classified.push({
      scheme:             scheme,
      raw:                u,
      oneClickEligible:   scheme === "https:",
    });
  }

  // RFC 8058 §2 — Post header value MUST be the canonical token.
  var postHeader = headers.listUnsubscribePost;
  var postHeaderOk = typeof postHeader === "string" && postHeader.trim() === ONE_CLICK_POST_VALUE;

  if (caps.requireHttpsUri && !hasHttpsUri) {
    return _verdict("refuse", "List-Unsubscribe has no https:// URI (RFC 8058 + Gmail/Yahoo bulk-sender 2024 requirement)",
      { uris: classified, hasHttpsUri: false, hasMailtoUri: hasMailtoUri, postHeaderOk: postHeaderOk });
  }
  if (caps.requirePostHeader && hasHttpsUri && !postHeaderOk) {
    var got = postHeader === undefined ? "(absent)" :
              typeof postHeader !== "string" ? "(non-string)" : postHeader;
    return _verdict("refuse",
      "List-Unsubscribe-Post header must be exactly '" + ONE_CLICK_POST_VALUE + "' (RFC 8058 §2); got " + got,
      { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: false });
  }

  return _verdict("accept", "headers compliant with RFC 2369 + RFC 8058",
    { uris: classified, hasHttpsUri: hasHttpsUri, hasMailtoUri: hasMailtoUri, postHeaderOk: postHeaderOk });
}

/**
 * @primitive b.guardListUnsubscribe.compliancePosture
 * @signature b.guardListUnsubscribe.compliancePosture(posture)
 * @since     0.9.39
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.guardListUnsubscribe.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _extractUris(raw, maxUris) {
  // RFC 2369 §3.1 — comma-separated `<URI>` items. Walk angle-
  // bracket pairs directly via String.matchAll so URIs containing
  // commas (legitimate, e.g. `<https://x/u?tags=a,b>`) parse
  // correctly. Earlier split(",")-based scan misclassified such
  // URIs as "no <URI> elements" and refused legitimate mail.
  var matches = raw.matchAll(/<([^<>]*)>/g);                                                             // allow:regex-no-length-cap — input length-bounded by maxBytes check upstream
  var uris = [];
  for (var m of matches) {
    uris.push(m[1].trim());
    if (uris.length > maxUris) return null;
  }
  return uris;
}

function _hasControlChar(s) {
  for (var i = 0; i < s.length; i += 1) {
    var c = s.charCodeAt(i);
    if (c === 0x00 || c === 0x7f || (c < 0x20 && c !== 0x09)) {                                          // RFC 5322 control + TAB allow
      return true;
    }
  }
  return false;
}

function _trunc(s) {
  if (s.length <= 64) return s;                                                                          // error-message truncation
  return s.slice(0, 60) + "…";                                                                          // allow:raw-time-literal — truncation char-count 60; coincidental multiple-of-60, not a duration, C.TIME N/A
}

function _verdict(action, reason, extra) {
  return {
    action:        action,
    reason:        reason,
    uris:          extra.uris,
    hasHttpsUri:   extra.hasHttpsUri,
    hasMailtoUri:  extra.hasMailtoUri,
    postHeaderOk:  extra.postHeaderOk,
    oneClickReady: extra.hasHttpsUri && extra.postHeaderOk,
  };
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return PROFILES[COMPLIANCE_POSTURES[opts.posture]];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardListUnsubscribeError("guard-list-unsubscribe/bad-profile",
      "guardListUnsubscribe: unknown profile '" + p + "'");
  }
  return PROFILES[p];
}

module.exports = {
  validate:                       validate,
  compliancePosture:              compliancePosture,
  PROFILES:                       PROFILES,
  COMPLIANCE_POSTURES:            COMPLIANCE_POSTURES,
  ONE_CLICK_POST_VALUE:           ONE_CLICK_POST_VALUE,
  DANGEROUS_SCHEMES:              DANGEROUS_SCHEMES,
  GuardListUnsubscribeError:      GuardListUnsubscribeError,
  NAME:                           "listUnsubscribe",
  KIND:                           "list-unsubscribe",
};
