"use strict";
/**
 * @module     b.guardListId
 * @nav        Guards
 * @title      Guard List-Id
 * @order      466
 *
 * @intro
 *   RFC 2919 `List-Id` header validator. Companion to
 *   `b.guardListUnsubscribe`; gates the outbound submission path so
 *   mailing-list mail carries a well-formed list identifier that
 *   downstream mail-client filters + bulk-sender pipelines can
 *   reliably route on.
 *
 *   ## RFC 2919 §2 ABNF
 *
 *   ```
 *   list-id           = list-label "." list-id-namespace
 *   list-label        = dot-atom-text       (RFC 5322)
 *   list-id-namespace = domain-name / "localhost"
 *   ```
 *
 *   Headers MAY surround the identifier in angle brackets and
 *   prepend a phrase + comment:
 *
 *   ```
 *   List-Id: My Newsletter <my-newsletter.example.com>
 *   List-Id: (Comment text) <list-12345.example.com>
 *   ```
 *
 *   This validator parses both bare-identifier and bracketed forms,
 *   refusing the address-list-injection class.
 *
 *   ## Defenses
 *
 *   - **Length cap** — RFC 2919 §3 caps the list identifier at 255
 *     octets. Total header value capped at 998 bytes per RFC 5322
 *     §2.1.1 line cap.
 *   - **CRLF + control-char refusal** — header-injection defense
 *     (CVE-2026-32178 — .NET CWE-138 header-injection spoofing, the
 *     System.Net.Mail vector per MSRC, on the wire-protocol surface;
 *     this primitive's job is the SEMANTIC shape).
 *   - **Phrase-injection refusal** — Operator-supplied display
 *     phrase mustn't carry CRLF / `<` / `>` outside the angle
 *     brackets (a separate Bcc/Cc header smuggled into the phrase
 *     fails the parse).
 *   - **Domain shape** — dot-atom-text per RFC 5322 §3.2.3; LDH
 *     labels per RFC 5321 §2.3.5; at least one `.` separator
 *     (rejects bare `mylist` claims).
 *   - **`localhost` namespace** — RFC 2919 §3 permits, but operator
 *     MUST also carry the recommended 32-hex random component when
 *     using `localhost`. Strict refuses unmanaged identifiers
 *     missing the randomness suffix (`SHOULD` semantics).
 *
 *   ## CVE / threat model
 *
 *   - **List-Id forging** — RFC 2919 §8 explicitly notes the
 *     identifier is NOT an authentication signal; this primitive
 *     refuses the SHAPE-injection class (mailing-list pipelines
 *     that crash or mis-route on malformed List-Id). Operators
 *     wanting authentication compose b.mail.auth.dmarc.evaluate /
 *     b.mail.auth.arc.verify on top.
 *   - **Bulk-sender bucket-drop** — Gmail's 2024 bulk-sender
 *     requirements key on List-Id presence for messages with
 *     `Precedence: list` or 5000+ daily sends; malformed List-Id
 *     drops the message into spam. This primitive surfaces the
 *     refuse-at-submit verdict so operators see the issue at
 *     send-time, not at delivery.
 *
 * @card
 *   RFC 2919 List-Id validator. Parses bare + bracketed + phrase-prefixed forms; refuses CRLF / control-char / phrase-injection / non-LDH domain / >255-octet identifier / bare-host claim. Companion to b.guardListUnsubscribe for outbound mailing-list compliance.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var gateContract       = require("./gate-contract");
var codepointClass     = require("./codepoint-class");

var GuardListIdError = defineClass("GuardListIdError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxBytes:           998,                                                                             // RFC 5322 §2.1.1 line cap
    maxListIdBytes:     255,                                                                             // RFC 2919 §3 cap
    requireFqdn:        true,
    requireRandomForLocalhost: true,
    allowPhrase:        true,
  },
  balanced: {
    maxBytes:           998,                                                                             // RFC 5322 §2.1.1 line cap
    maxListIdBytes:     255,                                                                             // RFC 2919 §3 cap
    requireFqdn:        true,
    requireRandomForLocalhost: false,
    allowPhrase:        true,
  },
  permissive: {
    maxBytes:           C.BYTES.kib(4),
    maxListIdBytes:     512,                                                                             // permissive max
    requireFqdn:        false,
    requireRandomForLocalhost: false,
    allowPhrase:        true,
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardListIdError,
  codePrefix: "guard-list-id",
  byObject:   true,
});

// RFC 5322 §3.2.3 dot-atom-text shape — alphanumeric + select
// printable specials. We don't allow the full atext set because
// the relaxed forms (`!`, `#`, `$`, etc.) almost never appear in
// real-world list IDs and the strictness defends parser drift in
// downstream consumers.
var DOT_ATOM_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$/;                                  // allow:regex-no-length-cap — per-label repeat-cap matches RFC 5321 §2.3.5
// 32-hex-char random component RFC 2919 §3 recommends for
// `localhost` namespace identifiers. We test for AT LEAST 32 hex
// chars somewhere in the list-label part.
var RANDOM_HEX_RE = /[0-9a-fA-F]{32}/;                                                                  // allow:regex-no-length-cap — anchored repeat-cap

/**
 * @primitive b.guardListId.validate
 * @signature b.guardListId.validate(headerValue, opts?)
 * @since     0.9.40
 * @status    stable
 * @related   b.guardListUnsubscribe.validate, b.guardEmail.validateMessage
 *
 * Validate an RFC 2919 `List-Id` header value. Accepts:
 *
 *   - `<my-list.example.com>` (bracketed bare-identifier form)
 *   - `My Newsletter <my-list.example.com>` (phrase + bracketed)
 *   - `my-list.example.com` (bare, no brackets — RFC 2919 allows)
 *
 * Returns `{ action, listId, namespace, phrase?, reason }`.
 * Action one of `"accept"` / `"refuse"`.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var v = b.guardListId.validate("My Newsletter <newsletter.example.com>");
 *   if (v.action === "accept") emit("List-Id: " + v.raw);
 */
function validate(headerValue, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  if (typeof headerValue !== "string") {
    throw new GuardListIdError("guard-list-id/bad-input",
      "validate: headerValue must be a string");
  }
  if (headerValue.length === 0) {
    return _refuse("empty List-Id header value");
  }
  if (Buffer.byteLength(headerValue, "utf8") > caps.maxBytes) {
    return _refuse("List-Id header exceeds maxBytes=" + caps.maxBytes + " (RFC 5322 §2.1.1)");
  }
  if (_hasControlChar(headerValue) || headerValue.indexOf("\r") !== -1 || headerValue.indexOf("\n") !== -1) {
    return _refuse("header contains CRLF / NUL / C0 / DEL (header-injection defense)");
  }

  // Extract optional phrase + bracketed identifier OR bare identifier.
  var trimmed = headerValue.trim();
  var phrase  = null;
  var listId  = null;
  var lt = trimmed.indexOf("<");
  if (lt !== -1) {
    var gt = trimmed.indexOf(">", lt + 1);
    if (gt === -1 || trimmed.indexOf("<", lt + 1) !== -1) {
      return _refuse("malformed angle brackets in List-Id");
    }
    if (gt !== trimmed.length - 1) {
      return _refuse("trailing content after '>' in List-Id");
    }
    phrase = trimmed.slice(0, lt).trim();
    listId = trimmed.slice(lt + 1, gt).trim();
    if (phrase.length > 0) {
      if (!caps.allowPhrase) {
        return _refuse("phrase before <list-id> refused by profile");
      }
      // Phrase-injection defense — phrase MUST NOT carry `<` / `>`
      // (would smuggle a second bracketed identifier).
      if (phrase.indexOf("<") !== -1 || phrase.indexOf(">") !== -1) {
        return _refuse("phrase contains '<' or '>' (List-Id smuggling defense)");
      }
    }
  } else {
    // Bare identifier — RFC 2919 §3 allows.
    listId = trimmed;
  }

  if (listId.length === 0) {
    return _refuse("empty list-id (RFC 2919 §3)");
  }
  if (Buffer.byteLength(listId, "utf8") > caps.maxListIdBytes) {
    return _refuse("list-id exceeds RFC 2919 §3 cap=" + caps.maxListIdBytes);
  }

  // RFC 2919 §2: `list-id = list-label "." list-id-namespace`.
  // Both sides are dot-atom-text, so string parsing alone can't
  // recover the boundary without Public Suffix List awareness
  // (`team.example.com` could be label=team / ns=example.com OR
  // label=team.example / ns=com). The earlier last-2-segment
  // heuristic produced empty `label` for 2-label IDs
  // which violates RFC 2919 §2's required label "."
  // namespace decomposition.
  //
  // Drop the heuristic split — surface only the raw `listId` (and
  // the parsed `phrase`). Consumers that need an org-domain split
  // compose `b.publicSuffix.organizationalDomain(listId)` directly,
  // which is PSL-accurate (handles `.co.uk`, `.com.au`, etc.).
  if (listId.indexOf(".") === -1) {
    return _refuse("list-id missing '.' separator (RFC 2919 §2; bare-host '" + listId + "')");
  }
  var parts = listId.split(".");
  for (var i = 0; i < parts.length; i += 1) {
    if (parts[i].length === 0) {
      return _refuse("empty label in list-id '" + listId + "' (RFC 5322 dot-atom-text)");
    }
    if (!DOT_ATOM_LABEL_RE.test(parts[i])) {                                                             // allow:regex-no-length-cap — label length-bounded by maxListIdBytes
      return _refuse("label '" + parts[i] + "' not dot-atom-text shape (RFC 5322 §3.2.3)");
    }
  }
  // RFC 2919 §2 requires AT LEAST one `.` (label + namespace);
  // strict/balanced ALSO require the namespace to be a FQDN, which
  // means a minimum of 3 labels total (label + ns-label + ns-tld) OR
  // a 2-label list-id where the namespace ends in a reserved-local
  // TLD: `localhost` (RFC 6761 §6.3), `local` (RFC 6762 mDNS), or
  // `lan` (IETF draft-chapin-rfc2606bis). All three are non-routable
  // single-network labels and the FQDN floor doesn't apply.
  var lastLabel = parts[parts.length - 1].toLowerCase();
  // List-Id (RFC 2919) is a dot-atom-text token NOT a wire-format
  // hostname; the value goes through dot-atom-text validation upstream
  // so a `localhost.` label-suffix is already refused at the segment-
  // shape level (an empty trailing segment fails the dot-atom-text
  // grammar). No trailing-dot bypass surface here.
  var isLocalScopeTld = lastLabel === "localhost" || lastLabel === "local" || lastLabel === "lan"; // allow:hostname-compare-trailing-dot-pre-split-refused — see comment above; List-Id parts already split on `.` so trailing-dot label is empty and refused upstream
  if (caps.requireFqdn) {
    if (parts.length < 3 && !isLocalScopeTld) {                                                          // FQDN requires ≥ 3 labels for non-local-scope namespace
      return _refuse("list-id has < 3 labels for non-local-scope namespace (FQDN required under '" +
        (opts.profile || DEFAULT_PROFILE) + "')");
    }
  }

  // RFC 2919 §3: `localhost`-class namespaces SHOULD carry 32-hex
  // randomness in the label so cross-host listserv operators can't
  // collide. Applies to all three reserved-local TLDs.
  if (isLocalScopeTld) {
    if (caps.requireRandomForLocalhost && !RANDOM_HEX_RE.test(listId)) {                                 // allow:regex-no-length-cap — listId length-bounded above
      return _refuse("local-scope namespace requires 32-hex random component per RFC 2919 §3 SHOULD");
    }
  }

  return {
    action:    "accept",
    listId:    listId,
    phrase:    phrase,
    reason:    "List-Id compliant with RFC 2919 §2",
  };
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

function _hasControlChar(s) {
  return codepointClass.firstControlCharOffset(s) !== -1;
}

function _refuse(reason) {
  return {
    action:    "refuse",
    listId:    null,
    phrase:    null,
    reason:    reason,
  };
}

module.exports = gateContract.defineParser({
  name:       "listId",
  entry:      validate,
  errorClass: GuardListIdError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "listId",
    KIND: "list-id",
  },
});
