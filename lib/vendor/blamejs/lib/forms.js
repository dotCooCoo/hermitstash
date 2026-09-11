// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.forms
 * @nav    HTTP
 * @title  Forms
 *
 * @intro
 *   HTML form rendering with CSRF token injection, accessible labels,
 *   field-type dispatch, and shared-spec server-side validation.
 *
 *   `b.forms.render(spec)` emits a complete `<form>` element with
 *   auto-escaped attributes, a hidden CSRF input, and per-field
 *   markup for text / email / password / number / checkbox / radio /
 *   textarea / select / hidden / submit. Every attribute value is
 *   forced through `escapeAttribute` so a hostile field name or value
 *   can't break out of the double-quoted attribute context.
 *
 *   `b.forms.validate(spec, body)` walks the same field spec the
 *   renderer accepts and returns `{ valid, errors, values }` —
 *   coerced types, required-field checks, length bounds, regex
 *   pattern, enum membership. Sharing the spec is the point: the
 *   operator's "this is what the form looks like" and "this is what
 *   the form expects" stay in lock-step, eliminating the drift class
 *   where a field gets added to the renderer but not the validator.
 *
 *   CSRF tokens are 32-byte hex strings from
 *   `b.crypto.generateToken`; `verifyCsrfToken` is constant-time.
 *   The middleware in `b.middleware.csrfProtect` does the actual
 *   request-time gating — this module supplies the issue / verify
 *   primitives.
 *
 * @card
 *   HTML form rendering with CSRF token injection, accessible labels, field-type dispatch, and shared-spec server-side validation.
 */
var C = require("./constants");
var { generateToken, timingSafeEqual } = require("./crypto");
var guardRegex = require("./guard-regex");
var safeSchema = require("./safe-schema");
var safeUrl = require("./safe-url");
var template = require("./template");

var CSRF_TOKEN_BYTES = C.BYTES.bytes(32);

var MAX_EMAIL_LENGTH = 254;
var MAX_URL_LENGTH   = C.BYTES.kib(8);

/**
 * @primitive b.forms.generateCsrfToken
 * @signature b.forms.generateCsrfToken()
 * @since     0.1.0
 * @status    stable
 * @related   b.forms.verifyCsrfToken, b.middleware.csrfProtect
 *
 * Returns a 32-byte (64 hex char) random token suitable for embedding
 * in a hidden form field. Entropy comes from `b.crypto.generateToken`,
 * which routes through Node's `crypto.randomBytes`. The token is
 * opaque to the framework — operators store it in the session and
 * compare via `verifyCsrfToken` on submit.
 *
 * @example
 *   var token = b.forms.generateCsrfToken();
 *   // → "8f3a1c4b...e7d9"   (64 hex chars)
 */
function generateCsrfToken() {
  return generateToken(CSRF_TOKEN_BYTES);
}

/**
 * @primitive b.forms.verifyCsrfToken
 * @signature b.forms.verifyCsrfToken(submitted, expected)
 * @since     0.1.0
 * @status    stable
 * @related   b.forms.generateCsrfToken, b.middleware.csrfProtect
 *
 * Constant-time comparison of a submitted token against the expected
 * value. Returns `false` for any non-string input, mismatched length,
 * or empty submitted token — never throws. Routes through
 * `b.crypto.timingSafeEqual` so an attacker can't probe character
 * positions via response-time differences.
 *
 * @example
 *   var ok = b.forms.verifyCsrfToken(req.body.csrf, req.session.csrf);
 *   // → true  (when both strings are non-empty and byte-identical)
 */
function verifyCsrfToken(submitted, expected) {
  if (typeof submitted !== "string" || typeof expected !== "string") return false;
  if (submitted.length === 0 || submitted.length !== expected.length) return false;
  return timingSafeEqual(submitted, expected);
}

var ATTR_ESCAPE_MAP = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;",
  '"': "&quot;", "'": "&#x27;",
  "`": "&#x60;", "=": "&#x3D;",
};
var ATTR_ESCAPE_RE = /[&<>"'`=]/g;

/**
 * @primitive b.forms.escapeAttribute
 * @signature b.forms.escapeAttribute(value)
 * @since     0.1.0
 * @status    stable
 * @related   b.forms.render, b.template.escapeHtml
 *
 * Escapes a value for safe interpolation into a double-quoted HTML
 * attribute context. Stricter than `b.template.escapeHtml`: also
 * escapes backtick (some browsers parse `` ` `` as an attribute
 * delimiter under quirks mode) and `=` (defense-in-depth for any
 * unquoted-attribute slips). `null` / `undefined` become the empty
 * string. Used internally by `b.forms.render` for every attribute
 * value; exported for operators rendering their own form fragments.
 *
 * @example
 *   var safe = b.forms.escapeAttribute('a"b<c>d');
 *   // → "a&quot;b&lt;c&gt;d"
 */
function escapeAttribute(value) {
  if (value === null || value === undefined) return "";
  var s = typeof value === "string" ? value : String(value);
  return s.replace(ATTR_ESCAPE_RE, function (c) { return ATTR_ESCAPE_MAP[c]; });
}

var INPUT_TYPES = {
  "text": 1, "email": 1, "password": 1, "number": 1, "tel": 1, "url": 1,
  "search": 1, "date": 1, "time": 1, "datetime-local": 1, "month": 1, "week": 1,
  "checkbox": 1, "radio": 1, "hidden": 1, "submit": 1, "color": 1,
  "file": 1, "range": 1, "image": 1, "reset": 1, "button": 1,
};

function _renderInput(field) {
  var attrs = [
    'type="' + escapeAttribute(field.type || "text") + '"',
    'name="' + escapeAttribute(field.name) + '"',
  ];
  if (field.value !== undefined && field.value !== null) {
    attrs.push('value="' + escapeAttribute(field.value) + '"');
  }
  if (field.placeholder)  attrs.push('placeholder="' + escapeAttribute(field.placeholder) + '"');
  if (field.required)     attrs.push("required");
  if (field.readonly)     attrs.push("readonly");
  if (field.disabled)     attrs.push("disabled");
  if (field.checked)      attrs.push("checked");
  if (field.autocomplete) attrs.push('autocomplete="' + escapeAttribute(field.autocomplete) + '"');
  if (field.pattern) {
    if (!(field.pattern instanceof RegExp)) {
      throw new Error("forms.render: field '" + field.name +
        "'.pattern must be a pre-compiled RegExp; got " +
        (typeof field.pattern) + ". Wrap the source string with `RegExp` at config time.");
    }
    guardRegex.assertSafe(field.pattern, "forms: field[" + field.name + "].pattern");
    attrs.push('pattern="' + escapeAttribute(field.pattern.source) + '"');
  }
  if (field.min !== undefined)        attrs.push('min="' + escapeAttribute(field.min) + '"');
  if (field.max !== undefined)        attrs.push('max="' + escapeAttribute(field.max) + '"');
  if (field.step !== undefined)       attrs.push('step="' + escapeAttribute(field.step) + '"');
  if (field.minlength !== undefined)  attrs.push('minlength="' + escapeAttribute(field.minlength) + '"');
  if (field.maxlength !== undefined)  attrs.push('maxlength="' + escapeAttribute(field.maxlength) + '"');
  if (field.id)           attrs.push('id="' + escapeAttribute(field.id) + '"');
  if (field.className)    attrs.push('class="' + escapeAttribute(field.className) + '"');
  return "<input " + attrs.join(" ") + ">";
}

function _renderTextarea(field) {
  var attrs = ['name="' + escapeAttribute(field.name) + '"'];
  if (field.placeholder)              attrs.push('placeholder="' + escapeAttribute(field.placeholder) + '"');
  if (field.required)                 attrs.push("required");
  if (field.readonly)                 attrs.push("readonly");
  if (field.disabled)                 attrs.push("disabled");
  if (field.rows !== undefined)       attrs.push('rows="' + escapeAttribute(field.rows) + '"');
  if (field.cols !== undefined)       attrs.push('cols="' + escapeAttribute(field.cols) + '"');
  if (field.minlength !== undefined)  attrs.push('minlength="' + escapeAttribute(field.minlength) + '"');
  if (field.maxlength !== undefined)  attrs.push('maxlength="' + escapeAttribute(field.maxlength) + '"');
  if (field.id)                       attrs.push('id="' + escapeAttribute(field.id) + '"');
  if (field.className)                attrs.push('class="' + escapeAttribute(field.className) + '"');
  var body = field.value !== undefined && field.value !== null ? template.escapeHtml(field.value) : "";
  return "<textarea " + attrs.join(" ") + ">" + body + "</textarea>";
}

function _renderSelect(field) {
  var attrs = ['name="' + escapeAttribute(field.name) + '"'];
  if (field.required)  attrs.push("required");
  if (field.disabled)  attrs.push("disabled");
  if (field.multiple)  attrs.push("multiple");
  if (field.id)        attrs.push('id="' + escapeAttribute(field.id) + '"');
  if (field.className) attrs.push('class="' + escapeAttribute(field.className) + '"');
  var options = field.options || [];
  var optionsHtml = options.map(function (o) {
    var optAttrs = ['value="' + escapeAttribute(o.value) + '"'];
    var selected = (o.selected) || (field.value !== undefined && String(field.value) === String(o.value));
    if (selected) optAttrs.push("selected");
    if (o.disabled) optAttrs.push("disabled");
    return "<option " + optAttrs.join(" ") + ">" + template.escapeHtml(o.label === undefined ? o.value : o.label) + "</option>";
  }).join("");
  return "<select " + attrs.join(" ") + ">" + optionsHtml + "</select>";
}

function _renderField(field) {
  if (!field || !field.name || typeof field.name !== "string") {
    throw new Error("forms.render: each field requires a name");
  }
  var type = field.type || "text";
  var control;
  if (type === "textarea") control = _renderTextarea(field);
  else if (type === "select") control = _renderSelect(field);
  else if (Object.prototype.hasOwnProperty.call(INPUT_TYPES, type))  control = _renderInput(field);
  else throw new Error("forms.render: unsupported field type: " + type);

  if (type === "hidden" || type === "submit") return control;

  if (field.label) {
    return "<label>" + template.escapeHtml(field.label) + " " + control + "</label>";
  }
  return control;
}

/**
 * @primitive b.forms.render
 * @signature b.forms.render(spec)
 * @since     0.1.0
 * @status    stable
 * @related   b.forms.validate, b.forms.generateCsrfToken, b.template.escapeHtml
 *
 * Renders a complete `<form>` element from a typed spec — method,
 * action, fields, optional CSRF token. Each field's `type` selects
 * the input widget (text / email / password / number / checkbox /
 * radio / textarea / select / hidden / submit). All attribute values
 * pass through `escapeAttribute`; `spec.csrfToken` (if present) is
 * embedded as a hidden `_csrf` input. Throws when `spec.action` is
 * missing / empty or `spec.fields` isn't an array.
 *
 * @example
 *   var html = b.forms.render({
 *     action:    "/login",
 *     method:    "POST",
 *     csrfToken: "8f3a1c4b...e7d9",
 *     fields: [
 *       { type: "email",    name: "email",    label: "Email",    required: true },
 *       { type: "password", name: "password", label: "Password", required: true },
 *       { type: "submit",   name: "submit",   value: "Sign in" },
 *     ],
 *   });
 *   // → "<form method=\"POST\" action=\"/login\">...<input type=\"hidden\" name=\"_csrf\" .../></form>"
 */
function render(spec) {
  if (!spec || typeof spec.action !== "string" || spec.action.length === 0) {
    throw new Error("forms.render: spec.action is required");
  }
  if (!Array.isArray(spec.fields)) {
    throw new Error("forms.render: spec.fields must be an array");
  }
  var method = (spec.method || "POST").toUpperCase();
  var attrs = [
    'method="' + escapeAttribute(method) + '"',
    'action="' + escapeAttribute(spec.action) + '"',
  ];
  if (spec.id)           attrs.push('id="' + escapeAttribute(spec.id) + '"');
  if (spec.className)    attrs.push('class="' + escapeAttribute(spec.className) + '"');
  if (spec.enctype)      attrs.push('enctype="' + escapeAttribute(spec.enctype) + '"');
  if (spec.autocomplete) attrs.push('autocomplete="' + escapeAttribute(spec.autocomplete) + '"');
  if (spec.target)       attrs.push('target="' + escapeAttribute(spec.target) + '"');

  var inner = "";

  if (spec.csrfToken && method !== "GET" && method !== "HEAD") {
    var csrfFieldName = spec.csrfFieldName || "_csrf";
    inner += '<input type="hidden" name="' + escapeAttribute(csrfFieldName) +
             '" value="' + escapeAttribute(spec.csrfToken) + '">';
  }

  for (var i = 0; i < spec.fields.length; i++) {
    inner += _renderField(spec.fields[i]);
  }

  var hasSubmit = spec.fields.some(function (f) { return f.type === "submit"; });
  if (!hasSubmit) {
    inner += '<button type="submit">' + template.escapeHtml(spec.submitLabel || "Submit") + "</button>";
  }

  return "<form " + attrs.join(" ") + ">" + inner + "</form>";
}

function _coerce(field, raw) {
  if (field.type === "checkbox") {
    if (raw === undefined || raw === null || raw === false || raw === 0) return false;
    return true;
  }
  if (raw === undefined) return undefined;
  switch (field.type) {
  case "number":
  case "range":
    if (raw === "" || raw === null) return null;
    var n = Number(raw);
    return Number.isFinite(n) ? n : NaN;
  case "date":
  case "datetime-local":
  case "time":
    return typeof raw === "string" ? raw : String(raw);
  default:
    return typeof raw === "string" ? raw : String(raw);
  }
}

function _isEmpty(v) {
  return v === undefined || v === null || v === "";
}

var NUMERIC_LITERAL_RE = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
var MAX_NUMERIC_BOUND_CHARS = 40;

function _numericBound(f, key) {
  var v = f[key];
  var n = NaN;
  if (typeof v === "number") n = v;
  else if (typeof v === "string" && v.length <= MAX_NUMERIC_BOUND_CHARS && NUMERIC_LITERAL_RE.test(v)) n = Number(v);
  if (!Number.isFinite(n)) {
    throw new Error("forms.validate: field '" + f.name + "'." + key +
      " must be a finite number; got " +
      (typeof v === "string" ? JSON.stringify(v) : typeof v) +
      ". Fix the form spec.");
  }
  return n;
}

function _assertFieldSpec(f) {
  if (!f.name || f.type === "submit") return;
  if (f.type === "number" || f.type === "range") {
    if (f.min !== undefined) _numericBound(f, "min");
    if (f.max !== undefined) _numericBound(f, "max");
  }
  if (f.minlength !== undefined) _numericBound(f, "minlength");
  if (f.maxlength !== undefined) _numericBound(f, "maxlength");
  if (f.pattern) {
    if (!(f.pattern instanceof RegExp)) {
      throw new Error("forms.validate: field '" + f.name +
        "'.pattern must be a pre-compiled RegExp; got " +
        (typeof f.pattern) + ". Wrap the source string with `RegExp` at config time.");
    }
    guardRegex.assertSafe(f.pattern, "forms: field[" + f.name + "].pattern");
  }
}

/**
 * @primitive b.forms.validate
 * @signature b.forms.validate(spec, body)
 * @since     0.1.0
 * @status    stable
 * @related   b.forms.render, b.safeSchema
 *
 * Walks the same spec the renderer accepts and validates a submitted
 * body. Per field: required-field check, type coercion (string /
 * number / boolean / email / url), `minlength` / `maxlength` bounds,
 * numeric `min` / `max` bounds, regex `pattern`, `enum` membership.
 * Returns
 * `{ valid: boolean, errors: { field: msg, ... }, values: { ... } }`.
 * The `values` object holds coerced values keyed by field name —
 * route handlers consume `result.values` directly without re-parsing.
 *
 * @example
 *   var result = b.forms.validate(
 *     { fields: [
 *         { type: "email",  name: "email", required: true },
 *         { type: "number", name: "age",   min: 1 },
 *     ] },
 *     { email: "ada@example.com", age: "37" }
 *   );
 *   // → { valid: true, errors: {}, values: { email: "ada@example.com", age: 37 } }
 */
function validate(spec, body) {
  if (!spec || !Array.isArray(spec.fields)) {
    throw new Error("forms.validate: spec.fields must be an array");
  }
  for (var s = 0; s < spec.fields.length; s++) {
    _assertFieldSpec(spec.fields[s]);
  }
  body = body || {};
  var errors = {};
  var values = {};

  for (var i = 0; i < spec.fields.length; i++) {
    var f = spec.fields[i];
    if (!f.name) continue;
    if (f.type === "submit") continue;

    var raw = body[f.name];
    var coerced = _coerce(f, raw);
    values[f.name] = coerced;

    if (f.type === "checkbox") {
      if (f.required && coerced !== true) {
        errors[f.name] = f.errorMessages && f.errorMessages.required
          ? f.errorMessages.required
          : (f.label || f.name) + " is required";
      }
      continue;
    }

    if (f.required && _isEmpty(coerced)) {
      errors[f.name] = f.errorMessages && f.errorMessages.required
        ? f.errorMessages.required
        : (f.label || f.name) + " is required";
      continue;
    }
    if (_isEmpty(coerced)) continue;

    if (f.type === "number" || f.type === "range") {
      if (Number.isNaN(coerced)) {
        errors[f.name] = (f.label || f.name) + " must be a number";
        continue;
      }
      if (f.min !== undefined && coerced < Number(f.min)) {
        errors[f.name] = (f.label || f.name) + " must be ≥ " + f.min;
        continue;
      }
      if (f.max !== undefined && coerced > Number(f.max)) {
        errors[f.name] = (f.label || f.name) + " must be ≤ " + f.max;
        continue;
      }
    }
    if (f.type === "email" && typeof coerced === "string") {
      if (coerced.length > MAX_EMAIL_LENGTH || !safeSchema.isEmail(coerced)) {
        errors[f.name] = (f.label || f.name) + " must be a valid email address";
        continue;
      }
    }
    if (f.type === "url" && typeof coerced === "string") {
      if (coerced.length > MAX_URL_LENGTH) {
        errors[f.name] = (f.label || f.name) + " must be a valid URL";
        continue;
      }
      try {
        safeUrl.parse(coerced, {
          allowedProtocols: f.allowHttp ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS,
        });
      } catch (_e) {
        errors[f.name] = (f.label || f.name) + " must be a valid URL";
        continue;
      }
    }
    if (typeof coerced === "string") {
      if (f.minlength !== undefined && coerced.length < Number(f.minlength)) {
        errors[f.name] = (f.label || f.name) + " must be at least " + f.minlength + " characters";
        continue;
      }
      if (f.maxlength !== undefined && coerced.length > Number(f.maxlength)) {
        errors[f.name] = (f.label || f.name) + " must be at most " + f.maxlength + " characters";
        continue;
      }
      if (f.pattern && !f.pattern.test(coerced)) {
        errors[f.name] = f.errorMessages && f.errorMessages.pattern
          ? f.errorMessages.pattern
          : (f.label || f.name) + " has an invalid format";
        continue;
      }
    }
    if ((f.type === "select" || f.type === "radio") && Array.isArray(f.options)) {
      var allowed = f.options.map(function (o) { return String(o.value); });
      if (allowed.indexOf(String(coerced)) === -1) {
        errors[f.name] = (f.label || f.name) + " has an invalid value";
        continue;
      }
    }
  }

  return {
    valid:   Object.keys(errors).length === 0,
    errors:  errors,
    values:  values,
  };
}

module.exports = {
  generateCsrfToken:  generateCsrfToken,
  verifyCsrfToken:    verifyCsrfToken,
  render:             render,
  validate:           validate,
  escapeAttribute:    escapeAttribute,
  escapeHtml:         template.escapeHtml,
  CSRF_TOKEN_BYTES:   CSRF_TOKEN_BYTES,
};
