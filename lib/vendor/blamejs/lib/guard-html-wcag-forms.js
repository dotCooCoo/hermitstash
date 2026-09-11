// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var codepointClass = require("./codepoint-class");
var validateOpts = require("./validate-opts");
var tagwalk = require("./guard-html-wcag-tagwalk");

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

  var collector = tagwalk.makeScopedFindings(opts.scopeUrl);
  var findings = collector.findings;
  var _add = collector.add;

  var found = tagwalk.tags(html);
  for (var t = 0; t < found.length; t += 1) {
    var m = found[t];
    if (m.closing) continue;
    var tagName = m.name;
    var attrs = tagwalk.parseAttrs(m.attrSrc);
    var pos = tagwalk.lineColAt(html, m.index);

    if (tagName === "fieldset") {
      var hasLegend = false;
      for (var c = t + 1; c < found.length; c += 1) {
        if (found[c].name === "fieldset" && found[c].closing) break;
        if (found[c].name === "legend" && !found[c].closing) { hasLegend = true; break; }
      }
      if (!hasLegend) {
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
      var tokens = codepointClass.splitOnWhitespace(v);
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
