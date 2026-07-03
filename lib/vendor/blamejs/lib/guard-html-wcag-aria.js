// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts = require("./validate-opts");
var tagwalk = require("./guard-html-wcag-tagwalk");

var KNOWN_ROLES = Object.freeze([
  "banner","complementary","contentinfo","form","main","navigation","region","search",
  "alert","alertdialog","log","marquee","status","timer",
  "article","definition","directory","document","feed","figure","group","heading","img",
  "list","listitem","math","note","presentation","none","row","rowgroup","rowheader",
  "separator","table","term","toolbar","tooltip",
  "button","checkbox","combobox","dialog","grid","gridcell","link","listbox","menu",
  "menubar","menuitem","menuitemcheckbox","menuitemradio","option","progressbar","radio",
  "radiogroup","scrollbar","searchbox","slider","spinbutton","switch","tab","tablist",
  "tabpanel","textbox","tree","treegrid","treeitem","application",
]);

var ROLE_REQUIRED_PROPS = Object.freeze({
  "checkbox":         ["aria-checked"],
  "switch":           ["aria-checked"],
  "radio":            ["aria-checked"],
  "menuitemradio":    ["aria-checked"],
  "menuitemcheckbox": ["aria-checked"],
  "combobox":         ["aria-expanded"],
  "scrollbar":        ["aria-valuenow"],
  "slider":           ["aria-valuenow"],
  "spinbutton":       ["aria-valuenow"],
  "heading":          ["aria-level"],
  "option":           ["aria-selected"],
});

var ARIA_VALUE_SETS = Object.freeze({
  "aria-checked":     ["true","false","mixed"],
  "aria-expanded":    ["true","false"],
  "aria-pressed":     ["true","false","mixed"],
  "aria-selected":    ["true","false"],
  "aria-disabled":    ["true","false"],
  "aria-hidden":      ["true","false"],
  "aria-haspopup":    ["false","true","menu","listbox","tree","grid","dialog"],
  "aria-orientation": ["horizontal","vertical"],
  "aria-current":     ["page","step","location","date","time","true","false"],
  "aria-live":        ["off","polite","assertive"],
  "aria-sort":        ["ascending","descending","none","other"],
  "aria-autocomplete":["inline","list","both","none"],
});

var _TAG_RE = tagwalk.TAG_RE;
var _parseAttrs = tagwalk.parseAttrs;
var _lineColAt = tagwalk.lineColAt;

function audit(html, opts) {
  opts = opts || {};
  validateOpts(opts, ["allowedRoles", "scopeUrl"], "guardHtml.wcag.aria.audit");
  if (typeof html !== "string") {
    throw new TypeError("aria.audit: html must be a string");
  }
  var allowedRoles = Array.isArray(opts.allowedRoles)
    ? KNOWN_ROLES.concat(opts.allowedRoles)
    : KNOWN_ROLES;

  // Per-finding scopeUrl stamping — shared collector in tagwalk.
  var collector = tagwalk.makeScopedFindings(opts.scopeUrl);
  var findings = collector.findings;
  var _add = collector.add;

  var declaredIds = Object.create(null);
  var idRe = /\bid\s*=\s*["']([^"']+)["']/gi;
  var im;
  while ((im = idRe.exec(html))) {                                                 // RegExp.prototype.exec
    declaredIds[im[1]] = true;
  }

  _TAG_RE.lastIndex = 0;
  var m;
  while ((m = _TAG_RE.exec(html))) {                                               // RegExp.prototype.exec
    if (m[0].charAt(1) === "/") continue;
    var tagName = m[1].toLowerCase();
    var attrs = _parseAttrs(m[2]);
    var offset = m.index;
    var pos = _lineColAt(html, offset);

    if ("role" in attrs) {
      var roles = attrs.role.split(/\s+/).filter(Boolean);
      for (var ri = 0; ri < roles.length; ri++) {
        if (allowedRoles.indexOf(roles[ri]) === -1) {
          _add({
            sc: "4.1.2", level: "A", severity: "warning",
            element: tagName, line: pos.line, column: pos.column,
            message: "Unknown ARIA role \"" + roles[ri] + "\" (typo? unsupported by AT?)",
            remediation: "Use a known WAI-ARIA 1.2 role or remove the role attribute",
          });
        }
      }
      for (var rj = 0; rj < roles.length; rj++) {
        var required = ROLE_REQUIRED_PROPS[roles[rj]];
        if (!Array.isArray(required) || required.length === 0) continue;
        for (var ai = 0; ai < required.length; ai++) {
          if (!(required[ai] in attrs)) {
            _add({
              sc: "4.1.2", level: "A", severity: "error",
              element: tagName, line: pos.line, column: pos.column,
              message: "ARIA role=\"" + roles[rj] + "\" requires attribute \"" + required[ai] + "\"",
              remediation: "Add " + required[ai] + "=\"<valid-value>\" to the element",
            });
          }
        }
      }
    }

    var attrNames = Object.keys(attrs);
    for (var ki = 0; ki < attrNames.length; ki++) {
      var key = attrNames[ki];
      if (key.indexOf("aria-") !== 0) continue;
      var allowedValues = ARIA_VALUE_SETS[key];
      if (!Array.isArray(allowedValues)) continue;
      var v = String(attrs[key]).trim();
      if (allowedValues.indexOf(v) === -1) {
        _add({
          sc: "4.1.2", level: "A", severity: "error",
          element: tagName, line: pos.line, column: pos.column,
          message: key + "=\"" + v + "\" is not in the allowed value set [" + allowedValues.join(", ") + "]",
          remediation: "Set " + key + " to one of the allowed values",
        });
      }
    }

    var refAttrs = ["aria-labelledby", "aria-controls", "aria-describedby"];
    for (var rai = 0; rai < refAttrs.length; rai++) {
      var refKey = refAttrs[rai];
      if (!(refKey in attrs)) continue;
      var idsRefd = attrs[refKey].split(/\s+/).filter(Boolean);
      for (var idi = 0; idi < idsRefd.length; idi++) {
        if (!declaredIds[idsRefd[idi]]) {
          _add({
            sc: "4.1.2", level: "A", severity: "error",
            element: tagName, line: pos.line, column: pos.column,
            message: refKey + "=\"" + idsRefd[idi] + "\" references id that is not declared in the document",
            remediation: "Either declare an element with id=\"" + idsRefd[idi] + "\" or remove the reference",
          });
        }
      }
    }

    if (attrs["aria-hidden"] === "true") {
      var interactive = ["a", "button", "input", "select", "textarea"].indexOf(tagName) !== -1;
      var hasTabindex = "tabindex" in attrs && attrs.tabindex !== "-1";
      if (interactive || hasTabindex) {
        _add({
          sc: "4.1.2", level: "A", severity: "error",
          element: tagName, line: pos.line, column: pos.column,
          message: "aria-hidden=\"true\" on interactive element",
          remediation: "Remove aria-hidden, or remove from focus order via tabindex=\"-1\" (and disable interactivity)",
        });
      }
    }
  }

  return findings;
}

module.exports = {
  audit:               audit,
  KNOWN_ROLES:         KNOWN_ROLES,
  ROLE_REQUIRED_PROPS: ROLE_REQUIRED_PROPS,
  ARIA_VALUE_SETS:     ARIA_VALUE_SETS,
};
