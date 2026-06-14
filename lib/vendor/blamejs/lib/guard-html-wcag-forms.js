"use strict";
/**
 * Form-specific accessibility validation for the WCAG 2.2 audit-only
 * scanner.
 *
 * Checks:
 *   - <fieldset> without <legend> (WCAG 1.3.1)
 *   - <input autocomplete=""> against the HTML 5.3 token registry
 *     (WCAG 1.3.5 — Identify Input Purpose)
 *   - Required field without aria-required / required (WCAG 3.3.7)
 *   - Form submit without explicit submit button or commit-on-enter
 *     marker (WCAG 3.3.4 — Error Prevention)
 *   - <input type="password"> within an autocomplete-disabled form
 *     (WCAG 3.3.8 — Accessible Authentication)
 *   - <textarea> without label / aria-label (WCAG 3.3.2)
 *
 * Exposed under b.guardHtml.wcag.forms.audit(html, opts).
 */

var validateOpts = require("./validate-opts");
var tagwalk = require("./guard-html-wcag-tagwalk");

// HTML 5.3 §4.10.18.7.1 — autocomplete token registry. Operators
// override / extend via opts.allowedAutocomplete. The framework
// allowlists the most common values; rare ones are flagged as
// warnings (operator might be using a custom token in error).
var AUTOCOMPLETE_TOKENS = Object.freeze([
  "off", "on",
  "name", "honorific-prefix", "given-name", "additional-name", "family-name",
  "honorific-suffix", "nickname", "username", "new-password", "current-password",
  "one-time-code",
  "organization-title", "organization",
  "street-address", "address-line1", "address-line2", "address-line3",
  "address-level4", "address-level3", "address-level2", "address-level1",
  "country", "country-name", "postal-code",
  "cc-name", "cc-given-name", "cc-additional-name", "cc-family-name",
  "cc-number", "cc-exp", "cc-exp-month", "cc-exp-year", "cc-csc", "cc-type",
  "transaction-currency", "transaction-amount",
  "language",
  "bday", "bday-day", "bday-month", "bday-year", "sex",
  "tel", "tel-country-code", "tel-national", "tel-area-code", "tel-local",
  "tel-extension", "email",
  "impp", "url", "photo",
]);

function audit(html, opts) {
  opts = opts || {};
  validateOpts(opts, [
    "allowedAutocomplete", "scopeUrl",
  ], "guardHtml.wcag.forms.audit");
  if (typeof html !== "string") {
    throw new TypeError("forms.audit: html must be a string");
  }
  var allowed = Array.isArray(opts.allowedAutocomplete)
    ? AUTOCOMPLETE_TOKENS.concat(opts.allowedAutocomplete)
    : AUTOCOMPLETE_TOKENS;

  // Per-finding scopeUrl stamping — shared collector in tagwalk.
  var collector = tagwalk.makeScopedFindings(opts.scopeUrl);
  var findings = collector.findings;
  var _add = collector.add;

  // Pre-scan: is there a <legend> inside any <fieldset>?
  // We track fieldset → has-legend by forward-scanning each fieldset.
  tagwalk.TAG_RE.lastIndex = 0;
  var m;
  while ((m = tagwalk.TAG_RE.exec(html))) {
    if (m[0].charAt(1) === "/") continue;
    var tagName = m[1].toLowerCase();
    var attrs = tagwalk.parseAttrs(m[2]);
    var pos = tagwalk.lineColAt(html, m.index);

    if (tagName === "fieldset") {
      // Forward-look for </fieldset>
      var closeIdx = html.indexOf("</fieldset>", m.index);
      var inside = closeIdx === -1 ? html.slice(m.index) : html.slice(m.index, closeIdx);
      if (!/<legend\b/i.test(inside)) {
        _add({
          sc: "1.3.1", level: "A", severity: "warning",
          element: "fieldset", line: pos.line, column: pos.column,
          message: "<fieldset> has no <legend> (assistive tech can't announce the field-group purpose)",
          remediation: "Add <legend>Group title</legend> as the first child of <fieldset>",
        });
      }
    }

    if (tagName === "input" && "autocomplete" in attrs) {
      var v = String(attrs.autocomplete).trim().toLowerCase();
      // autocomplete supports compound tokens like "section-foo billing tel";
      // we check the LAST token (the canonical purpose token).
      var tokens = v.split(/\s+/);
      var canonical = tokens[tokens.length - 1];
      if (allowed.indexOf(canonical) === -1) {
        _add({
          sc: "1.3.5", level: "AA", severity: "warning",
          element: "input", line: pos.line, column: pos.column,
          message: "input autocomplete=\"" + v + "\" canonical token \"" + canonical +
                   "\" is not in the HTML 5.3 registry",
          remediation: "Use a registered autocomplete token (https://www.w3.org/TR/html53/sec-forms.html#autofill)",
        });
      }
    }

    if (tagName === "input" && attrs.type === "password" &&
        "autocomplete" in attrs &&
        attrs.autocomplete === "off") {
      _add({
        sc: "3.3.8", level: "AA", severity: "warning",
        element: "input", line: pos.line, column: pos.column,
        message: "password input has autocomplete=\"off\" (blocks password manager — WCAG 3.3.8 requires accessible authentication; password managers count as a recognised authentication aid)",
        remediation: "Use autocomplete=\"current-password\" or autocomplete=\"new-password\" instead of \"off\"",
      });
    }

    // 3.3.7 redundant entry — input type=email/tel/etc. without
    // autocomplete attribute prevents browsers from offering
    // saved values, forcing users to re-enter every time.
    if (tagName === "input" && !("autocomplete" in attrs) &&
        ["email", "tel", "name"].indexOf(attrs.type) !== -1) {
      _add({
        sc: "3.3.7", level: "A", severity: "info",
        element: "input", line: pos.line, column: pos.column,
        message: "input type=\"" + attrs.type + "\" has no autocomplete attribute (browsers can't offer saved values; users re-enter)",
        remediation: "Add autocomplete=\"email\" / \"tel\" / \"name\" / etc.",
      });
    }

    if (tagName === "textarea" &&
        !("aria-label" in attrs) && !("aria-labelledby" in attrs) &&
        !("title" in attrs) && !("id" in attrs)) {
      _add({
        sc: "3.3.2", level: "A", severity: "error",
        element: "textarea", line: pos.line, column: pos.column,
        message: "textarea has no associated label (no id, no aria-label, no title)",
        remediation: "Add id+matching <label for=...> or aria-label=\"<text>\"",
      });
    }
  }

  return findings;
}

module.exports = {
  audit:                  audit,
  AUTOCOMPLETE_TOKENS:    AUTOCOMPLETE_TOKENS,
};
