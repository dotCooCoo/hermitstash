// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.forms — canonical coverage of the form primitives: CSRF token
 * issue/verify, attribute escaping, spec-driven `<form>` rendering, and
 * shared-spec server-side validation.
 *
 * Drives the real b.forms.* consumer surface (never requires lib/forms
 * directly): generateCsrfToken / verifyCsrfToken / escapeAttribute /
 * render / validate. Covers every field-type render branch, the CSRF
 * hidden-input method gating, the config-time throws (missing action,
 * non-array fields, unnamed field, unsupported type, string pattern,
 * ReDoS pattern), and validate's coercion + required + numeric bounds +
 * email/url + length + pattern + enum paths across the returned
 * { valid, errors, values } shape.
 *
 * Run standalone: `node test/layer-0-primitives/forms.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

// Returns true iff fn() throws. Keeps the config-time-throw assertions
// terse without a bespoke harness (audit-existing applies to tests too).
function _throws(fn) {
  try { fn(); return false; } catch (_e) { return true; }
}

// ============================================================
// generateCsrfToken
// ============================================================

function testGenerateCsrfToken() {
  var t1 = b.forms.generateCsrfToken();
  var t2 = b.forms.generateCsrfToken();
  check("generateCsrfToken: 64 hex chars", /^[0-9a-f]{64}$/.test(t1));
  check("generateCsrfToken: exactly 64 chars long", t1.length === 64);
  check("generateCsrfToken: distinct per call", t1 !== t2);
  check("forms.CSRF_TOKEN_BYTES is 32", b.forms.CSRF_TOKEN_BYTES === 32);
}

// ============================================================
// verifyCsrfToken
// ============================================================

function testVerifyCsrfToken() {
  var t = b.forms.generateCsrfToken();
  check("verify: identical real tokens → true", b.forms.verifyCsrfToken(t, t) === true);
  check("verify: byte-equal non-empty strings → true", b.forms.verifyCsrfToken("abc", "abc") === true);
  check("verify: distinct real tokens → false", b.forms.verifyCsrfToken(t, b.forms.generateCsrfToken()) === false);
  check("verify: same-length mismatch → false", b.forms.verifyCsrfToken("abc", "abd") === false);
  check("verify: length mismatch → false", b.forms.verifyCsrfToken("abc", "abcd") === false);
  check("verify: empty submitted vs empty expected → false", b.forms.verifyCsrfToken("", "") === false);
  check("verify: empty submitted vs non-empty → false", b.forms.verifyCsrfToken("", "abc") === false);
  check("verify: non-string submitted → false", b.forms.verifyCsrfToken(123, "abc") === false);
  check("verify: non-string expected → false", b.forms.verifyCsrfToken("abc", 123) === false);
  check("verify: both non-string → false", b.forms.verifyCsrfToken(null, null) === false);
  // Documented contract: never throws, whatever the input type.
  var threw = _throws(function () {
    b.forms.verifyCsrfToken(undefined, undefined);
    b.forms.verifyCsrfToken({}, []);
    b.forms.verifyCsrfToken(NaN, "x");
  });
  check("verify: never throws on adversarial inputs", threw === false);
}

// ============================================================
// escapeAttribute
// ============================================================

function testEscapeAttribute() {
  check("escape: null → empty string", b.forms.escapeAttribute(null) === "");
  check("escape: undefined → empty string", b.forms.escapeAttribute(undefined) === "");
  check("escape: every special char escaped",
        b.forms.escapeAttribute("&<>\"'`=") === "&amp;&lt;&gt;&quot;&#x27;&#x60;&#x3D;");
  check("escape: plain string unchanged", b.forms.escapeAttribute("plain-value") === "plain-value");
  check("escape: number coerced via String()", b.forms.escapeAttribute(42) === "42");
  check("escape: falsy zero coerced (not treated as null)", b.forms.escapeAttribute(0) === "0");
  check("escape: boolean false coerced", b.forms.escapeAttribute(false) === "false");
  check("escape: boolean true coerced", b.forms.escapeAttribute(true) === "true");
}

// ============================================================
// render — config-time throws
// ============================================================

function testRenderThrows() {
  check("render: no spec throws", _throws(function () { return b.forms.render(); }));
  check("render: null spec throws", _throws(function () { return b.forms.render(null); }));
  check("render: non-string action throws", _throws(function () { return b.forms.render({ action: 123, fields: [] }); }));
  check("render: empty action throws", _throws(function () { return b.forms.render({ action: "", fields: [] }); }));
  check("render: non-array fields throws", _throws(function () { return b.forms.render({ action: "/x", fields: "nope" }); }));
  check("render: field without name throws", _throws(function () { return b.forms.render({ action: "/x", fields: [{ type: "text" }] }); }));
  check("render: null field throws", _throws(function () { return b.forms.render({ action: "/x", fields: [null] }); }));
  check("render: non-string field name throws", _throws(function () { return b.forms.render({ action: "/x", fields: [{ name: 123 }] }); }));
  check("render: unsupported field type throws", _throws(function () { return b.forms.render({ action: "/x", fields: [{ type: "frobnicate", name: "f" }] }); }));
  check("render: string pattern throws (must be pre-compiled RegExp)",
        _throws(function () { return b.forms.render({ action: "/x", fields: [{ type: "text", name: "p", pattern: "^abc$" }] }); }));
  check("render: catastrophic-backtracking pattern refused at config time",
        _throws(function () { return b.forms.render({ action: "/x", fields: [{ type: "text", name: "p", pattern: /(a+)+/ }] }); }));
}

// ============================================================
// render — form-level attributes, method + CSRF gating
// ============================================================

function testRenderFormAttrs() {
  var html = b.forms.render({
    action:       "/submit",
    method:       "post",                 // lower-case → upper-cased
    csrfToken:    "tok<en>",
    id:           "form-id",
    className:    "form-class",
    enctype:      "multipart/form-data",
    autocomplete: "off",
    target:       "_blank",
    fields:       [{ type: "text", name: "q" }],
  });
  check("render: opens with <form", html.indexOf("<form ") === 0);
  check("render: method upper-cased", html.indexOf('method="POST"') !== -1);
  check("render: action attr", html.indexOf('action="/submit"') !== -1);
  check("render: id attr", html.indexOf('id="form-id"') !== -1);
  check("render: class attr", html.indexOf('class="form-class"') !== -1);
  check("render: enctype attr", html.indexOf('enctype="multipart/form-data"') !== -1);
  check("render: autocomplete attr", html.indexOf('autocomplete="off"') !== -1);
  check("render: target attr", html.indexOf('target="_blank"') !== -1);
  check("render: csrf hidden input on POST", html.indexOf('<input type="hidden" name="_csrf"') !== -1);
  check("render: csrf token value escaped in attribute", html.indexOf('value="tok&lt;en&gt;"') !== -1);
  check("render: closes with </form>", html.indexOf("</form>") === html.length - 7);
}

function testRenderCsrfGating() {
  var post = b.forms.render({ action: "/a", method: "POST", csrfToken: "t", fields: [] });
  check("render: POST with token renders csrf input", post.indexOf('name="_csrf"') !== -1);

  var get = b.forms.render({ action: "/a", method: "GET", csrfToken: "t", fields: [] });
  check("render: GET omits csrf even when token supplied", get.indexOf("_csrf") === -1);

  var head = b.forms.render({ action: "/a", method: "HEAD", csrfToken: "t", fields: [] });
  check("render: HEAD omits csrf even when token supplied", head.indexOf("_csrf") === -1);

  var noToken = b.forms.render({ action: "/a", method: "POST", fields: [] });
  check("render: POST without token has no csrf input", noToken.indexOf("_csrf") === -1);

  var custom = b.forms.render({ action: "/a", method: "POST", csrfToken: "t", csrfFieldName: "xsrf", fields: [] });
  check("render: custom csrfFieldName honored",
        custom.indexOf('name="xsrf"') !== -1 && custom.indexOf('name="_csrf"') === -1);

  var deflt = b.forms.render({ action: "/a", fields: [] });   // method defaults to POST
  check("render: method defaults to POST", deflt.indexOf('method="POST"') !== -1);
}

// ============================================================
// render — input widget attributes
// ============================================================

function testRenderInputAttrs() {
  var html = b.forms.render({
    action: "/x",
    fields: [{
      type: "text", name: "kitchen",
      value: "v", placeholder: "p", required: true, readonly: true,
      disabled: true, checked: true, autocomplete: "username",
      pattern: /^[a-z]+$/, min: 0, max: 10, step: 2,
      minlength: 1, maxlength: 5, id: "kid", className: "kc",
    }],
  });
  check("input: type attr", html.indexOf('type="text"') !== -1);
  check("input: name attr", html.indexOf('name="kitchen"') !== -1);
  check("input: value attr", html.indexOf('value="v"') !== -1);
  check("input: placeholder attr", html.indexOf('placeholder="p"') !== -1);
  check("input: required flag", html.indexOf(" required") !== -1);
  check("input: readonly flag", html.indexOf(" readonly") !== -1);
  check("input: disabled flag", html.indexOf(" disabled") !== -1);
  check("input: checked flag", html.indexOf(" checked") !== -1);
  check("input: autocomplete attr", html.indexOf('autocomplete="username"') !== -1);
  check("input: pattern source rendered from RegExp", html.indexOf('pattern="^[a-z]+$"') !== -1);
  check("input: min attr (zero emitted)", html.indexOf('min="0"') !== -1);
  check("input: max attr", html.indexOf('max="10"') !== -1);
  check("input: step attr", html.indexOf('step="2"') !== -1);
  check("input: minlength attr", html.indexOf('minlength="1"') !== -1);
  check("input: maxlength attr", html.indexOf('maxlength="5"') !== -1);
  check("input: id attr", html.indexOf('id="kid"') !== -1);
  check("input: class attr", html.indexOf('class="kc"') !== -1);
}

function testRenderInputValuePresence() {
  var withEmpty = b.forms.render({ action: "/x", fields: [{ type: "text", name: "e", value: "" }] });
  check("input: empty-string value still emits value attr", withEmpty.indexOf('value=""') !== -1);

  var withNull = b.forms.render({ action: "/x", fields: [{ type: "text", name: "n", value: null }] });
  check("input: null value omits value attr", withNull.indexOf("value=") === -1);

  var noValue = b.forms.render({ action: "/x", fields: [{ type: "text", name: "u" }] });
  check("input: undefined value omits value attr", noValue.indexOf("value=") === -1);
}

// ============================================================
// render — textarea
// ============================================================

function testRenderTextarea() {
  var html = b.forms.render({
    action: "/x",
    fields: [{
      type: "textarea", name: "bio", value: "hi<b>", placeholder: "p",
      required: true, readonly: true, disabled: true,
      rows: 4, cols: 20, minlength: 2, maxlength: 500, id: "tid", className: "tc",
    }],
  });
  check("textarea: name attr", html.indexOf('<textarea name="bio"') !== -1);
  check("textarea: placeholder attr", html.indexOf('placeholder="p"') !== -1);
  check("textarea: required flag", html.indexOf(" required") !== -1);
  check("textarea: readonly flag", html.indexOf(" readonly") !== -1);
  check("textarea: disabled flag", html.indexOf(" disabled") !== -1);
  check("textarea: rows attr", html.indexOf('rows="4"') !== -1);
  check("textarea: cols attr", html.indexOf('cols="20"') !== -1);
  check("textarea: minlength attr", html.indexOf('minlength="2"') !== -1);
  check("textarea: maxlength attr", html.indexOf('maxlength="500"') !== -1);
  check("textarea: id attr", html.indexOf('id="tid"') !== -1);
  check("textarea: class attr", html.indexOf('class="tc"') !== -1);
  check("textarea: body html-escaped", html.indexOf(">hi&lt;b&gt;</textarea>") !== -1);

  var empty = b.forms.render({ action: "/x", fields: [{ type: "textarea", name: "t" }] });
  check("textarea: no value → empty body", empty.indexOf('<textarea name="t"></textarea>') !== -1);
}

// ============================================================
// render — select
// ============================================================

function testRenderSelect() {
  var html = b.forms.render({
    action: "/x",
    fields: [{
      type: "select", name: "sel", value: "b", required: true, disabled: true,
      multiple: true, id: "sid", className: "sc",
      options: [
        { value: "a", label: "A" },
        { value: "b" },
        { value: "c", label: "C", selected: true },
        { value: "d", label: "D", disabled: true },
      ],
    }],
  });
  check("select: name attr", html.indexOf('<select name="sel"') !== -1);
  check("select: required flag", html.indexOf(" required") !== -1);
  check("select: disabled flag", html.indexOf(" disabled") !== -1);
  check("select: multiple flag", html.indexOf(" multiple") !== -1);
  check("select: id attr", html.indexOf('id="sid"') !== -1);
  check("select: class attr", html.indexOf('class="sc"') !== -1);
  check("select: unselected option rendered", html.indexOf('<option value="a">A</option>') !== -1);
  check("select: option selected via field.value match, label falls back to value",
        html.indexOf('<option value="b" selected>b</option>') !== -1);
  check("select: option selected via o.selected", html.indexOf('<option value="c" selected>C</option>') !== -1);
  check("select: disabled option", html.indexOf('<option value="d" disabled>D</option>') !== -1);

  var noOptions = b.forms.render({ action: "/x", fields: [{ type: "select", name: "empty" }] });
  check("select: missing options → empty select", noOptions.indexOf('<select name="empty"></select>') !== -1);

  var noValue = b.forms.render({
    action: "/x",
    fields: [{ type: "select", name: "s2", options: [{ value: "a", label: "A" }, { value: "b", label: "B" }] }],
  });
  check("select: no field.value → no option auto-selected", noValue.indexOf("selected") === -1);
}

// ============================================================
// render — field-type dispatch, labels, submit button
// ============================================================

function testRenderFieldTypesAndLabels() {
  var types = [
    "text", "email", "password", "number", "tel", "url", "search", "date",
    "time", "datetime-local", "month", "week", "checkbox", "radio", "hidden",
    "color", "file", "range", "image", "reset", "button",
  ];
  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    var h = b.forms.render({ action: "/x", fields: [{ type: t, name: "f" }] });
    check("render: input widget for type " + t, h.indexOf('type="' + t + '"') !== -1);
  }

  var labeled = b.forms.render({ action: "/x", fields: [{ type: "email", name: "e", label: "Email <addr>" }] });
  check("render: label wraps control (label html-escaped)",
        labeled.indexOf("<label>Email &lt;addr&gt; <input") !== -1);

  var hidden = b.forms.render({ action: "/x", fields: [{ type: "hidden", name: "h", value: "x", label: "ignored" }] });
  check("render: hidden field skips label wrapper", hidden.indexOf("<label>") === -1);

  var submit = b.forms.render({ action: "/x", fields: [{ type: "submit", name: "s", value: "Go", label: "ignored" }] });
  check("render: submit field skips label wrapper", submit.indexOf("<label>") === -1);

  // A field with no `type` defaults to a text input — the dispatch
  // (_renderField's `|| "text"`) and the emitted type attribute both
  // resolve to "text", so the rendered markup stays self-consistent.
  var deflt = b.forms.render({ action: "/x", fields: [{ name: "d" }] });
  check("render: no-type field defaults to a text input", deflt.indexOf('<input type="text" name="d">') !== -1);
}

function testRenderSubmitButton() {
  var withSubmitInput = b.forms.render({ action: "/x", fields: [{ type: "submit", name: "s", value: "Go" }] });
  check("render: explicit submit field suppresses auto button", withSubmitInput.indexOf('<button type="submit">') === -1);
  check("render: explicit submit field renders as input", withSubmitInput.indexOf('<input type="submit" name="s" value="Go">') !== -1);

  var auto = b.forms.render({ action: "/x", fields: [] });
  check("render: no submit field → default Submit button", auto.indexOf('<button type="submit">Submit</button>') !== -1);

  var customLabel = b.forms.render({ action: "/x", submitLabel: "Send <it>", fields: [] });
  check("render: custom submitLabel html-escaped in auto button",
        customLabel.indexOf('<button type="submit">Send &lt;it&gt;</button>') !== -1);
}

// ============================================================
// validate — config-time throws
// ============================================================

function testValidateThrows() {
  check("validate: no spec throws", _throws(function () { return b.forms.validate(); }));
  check("validate: non-array fields throws", _throws(function () { return b.forms.validate({ fields: "x" }, {}); }));
  check("validate: string pattern throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "text", name: "p", pattern: "^abc$" }] }, { p: "abc" }); }));
  check("validate: catastrophic-backtracking pattern refused before test",
        _throws(function () { return b.forms.validate({ fields: [{ type: "text", name: "p", pattern: /(a+)+/ }] }, { p: "aaa" }); }));
}

// ============================================================
// validate — required, shape, skips
// ============================================================

function testValidateRequiredAndShape() {
  var r = b.forms.validate({ fields: [{ type: "text", name: "name", required: true, label: "Name" }] }, {});
  check("validate: missing required field → invalid", r.valid === false);
  check("validate: required message uses label", r.errors.name === "Name is required");
  check("validate: result exposes valid/errors/values",
        typeof r.valid === "boolean" && !!r.errors && !!r.values &&
        Object.prototype.hasOwnProperty.call(r.values, "name"));

  var r2 = b.forms.validate({ fields: [{ type: "text", name: "email", required: true, errorMessages: { required: "Give an email" } }] }, {});
  check("validate: custom errorMessages.required used", r2.errors.email === "Give an email");

  var r3 = b.forms.validate({ fields: [{ type: "text", name: "name", required: true }] }, { name: "ada" });
  check("validate: satisfied required field → valid",
        r3.valid === true && r3.errors.name === undefined && r3.values.name === "ada");

  var r4 = b.forms.validate({ fields: [{ type: "text", name: "name", required: true }] }, { name: "" });
  check("validate: empty string for required → invalid (default message)",
        r4.valid === false && r4.errors.name === "name is required");

  var noBody = b.forms.validate({ fields: [{ type: "text", name: "x", required: true, label: "X" }] });
  check("validate: omitted body defaults to empty object", noBody.valid === false && noBody.errors.x === "X is required");
}

function testValidateSkips() {
  var r = b.forms.validate({ fields: [
    { type: "submit", name: "s", value: "Go" },
    { type: "text" },                                 // no name
    { type: "text", name: "keep" },
  ] }, { s: "Go", keep: "hello" });
  check("validate: submit field excluded from values", Object.prototype.hasOwnProperty.call(r.values, "s") === false);
  check("validate: named non-submit field kept", r.values.keep === "hello");
  check("validate: unnamed field produces no value entry", Object.keys(r.values).length === 1);

  var r2 = b.forms.validate({ fields: [{ type: "text", name: "opt" }] }, {});
  check("validate: optional absent field coerces to undefined",
        Object.prototype.hasOwnProperty.call(r2.values, "opt") && r2.values.opt === undefined);
}

// ============================================================
// validate — coercion (checkbox / number / range / date / default)
// ============================================================

function testValidateCheckboxCoercion() {
  function chk(body) {
    return b.forms.validate({ fields: [{ type: "checkbox", name: "c" }] }, body).values.c;
  }
  // Unchecked: the field is absent (undefined / null) or, from a typed
  // (JSON) body, an explicit boolean false / numeric 0.
  check("checkbox: unchecked (absent) → false", chk({}) === false);
  check("checkbox: null → false", chk({ c: null }) === false);
  check("checkbox: JSON boolean false → false", chk({ c: false }) === false);
  check("checkbox: JSON numeric 0 → false", chk({ c: 0 }) === false);
  // Checked: any PRESENT string (a urlencoded checkbox submits its value
  // string only when ticked — the value's content is irrelevant), plus a
  // typed truthy value.
  check("checkbox: 'on' → true", chk({ c: "on" }) === true);
  check("checkbox: empty-string value (present) → true", chk({ c: "" }) === true);
  check("checkbox: custom value 'false' string (present) → true", chk({ c: "false" }) === true);
  check("checkbox: custom value '0' string (present) → true", chk({ c: "0" }) === true);
  check("checkbox: boolean true → true", chk({ c: true }) === true);
  check("checkbox: JSON numeric 1 → true", chk({ c: 1 }) === true);
}

function testValidateRequiredCheckbox() {
  // A required checkbox must be CHECKED. HTML defines `required` on a
  // checkbox as "must be ticked," and the renderer emits that attribute —
  // so server-side validate() enforces the same (the backend validates
  // what the frontend displays). An unchecked required box is an error,
  // not a silent pass.
  var unchecked = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true, label: "Terms" }] }, {});
  check("checkbox: required + unchecked (absent) → invalid",
        unchecked.valid === false && unchecked.errors.tos === "Terms is required");

  // A checkbox rendered with a custom value (even "false") submits that
  // literal only when ticked, so presence satisfies the requirement.
  var customValChecked = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true }] }, { tos: "false" });
  check("checkbox: required + present string value (checked) → valid",
        customValChecked.valid === true && customValChecked.values.tos === true);

  // JSON bodies deliver an unchecked box as boolean false / numeric 0 — a
  // non-browser caller must not bypass the required check with either.
  var jsonFalse = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true }] }, { tos: false });
  check("checkbox: required + JSON boolean false → invalid",
        jsonFalse.valid === false && jsonFalse.errors.tos === "tos is required");

  var jsonZero = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true }] }, { tos: 0 });
  check("checkbox: required + JSON numeric 0 → invalid",
        jsonZero.valid === false && jsonZero.errors.tos === "tos is required");

  var checked = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true }] }, { tos: "on" });
  check("checkbox: required + checked → valid", checked.valid === true && checked.values.tos === true);

  var custom = b.forms.validate({ fields: [{ type: "checkbox", name: "tos", required: true, errorMessages: { required: "Accept the terms" } }] }, {});
  check("checkbox: required uses custom errorMessages.required",
        custom.valid === false && custom.errors.tos === "Accept the terms");

  var optional = b.forms.validate({ fields: [{ type: "checkbox", name: "news" }] }, {});
  check("checkbox: optional + unchecked → valid (coerced false)",
        optional.valid === true && optional.values.news === false);
}

function testValidateNumberCoercionAndBounds() {
  var num = b.forms.validate({ fields: [{ type: "number", name: "age" }] }, { age: "37" });
  check("number: numeric string coerced to Number", num.values.age === 37 && num.valid === true);

  var empty = b.forms.validate({ fields: [{ type: "number", name: "age" }] }, { age: "" });
  check("number: empty string coerces to null", empty.values.age === null && empty.valid === true);

  var nullish = b.forms.validate({ fields: [{ type: "number", name: "age" }] }, { age: null });
  check("number: null coerces to null", nullish.values.age === null);

  var nan = b.forms.validate({ fields: [{ type: "number", name: "age", label: "Age" }] }, { age: "abc" });
  check("number: non-numeric → NaN → error", nan.valid === false && nan.errors.age === "Age must be a number");

  var lo = b.forms.validate({ fields: [{ type: "number", name: "age", min: 10 }] }, { age: "5" });
  check("number: below min → error", lo.valid === false && typeof lo.errors.age === "string");

  var hi = b.forms.validate({ fields: [{ type: "number", name: "age", max: 100 }] }, { age: "150" });
  check("number: above max → error", hi.valid === false && typeof hi.errors.age === "string");

  var ok = b.forms.validate({ fields: [{ type: "number", name: "age", min: 0, max: 120 }] }, { age: "42" });
  check("number: within bounds → valid", ok.valid === true && ok.values.age === 42);

  var zero = b.forms.validate({ fields: [{ type: "number", name: "age", required: true }] }, { age: "0" });
  check("number: zero satisfies required (not treated as empty)", zero.valid === true && zero.values.age === 0);

  var reqEmpty = b.forms.validate({ fields: [{ type: "number", name: "age", required: true, label: "Age" }] }, { age: "" });
  check("number: empty required number → required error", reqEmpty.valid === false && reqEmpty.errors.age === "Age is required");

  var range = b.forms.validate({ fields: [{ type: "range", name: "vol", min: 0, max: 11 }] }, { vol: "12" });
  check("range: shares numeric bounds path (above max)", range.valid === false && typeof range.errors.vol === "string");

  var rangeNan = b.forms.validate({ fields: [{ type: "range", name: "vol" }] }, { vol: "x" });
  check("range: non-numeric → NaN error", rangeNan.valid === false && typeof rangeNan.errors.vol === "string");
}

function testValidateNumericBoundConfig() {
  // A defined-but-non-numeric bound (min/max/minlength/maxlength) is an
  // operator config error: the comparison would silently never fire (NaN
  // comparisons are always false), so the bound is a no-op rather than the
  // guarantee the spec implies. validate() throws at the entry point,
  // matching the string-pattern throw — a malformed spec fails loudly.
  check("validate: non-numeric min throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: "abc" }] }, { n: "5" }); }));
  check("validate: non-numeric max throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", max: "xyz" }] }, { n: "5" }); }));
  check("validate: non-numeric minlength throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "text", name: "s", minlength: "two" }] }, { s: "abcd" }); }));
  check("validate: non-numeric maxlength throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "text", name: "s", maxlength: "big" }] }, { s: "abcd" }); }));
  check("validate: Infinity bound throws (must be finite)",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", max: Infinity }] }, { n: "5" }); }));

  // Number()-coercible junk (null / "" / whitespace / boolean / array) must
  // NOT be accepted as a bound of 0/1 — those are malformed specs, and
  // silently treating them as numeric diverges from the rendered constraint.
  check("validate: null bound throws (not coerced to 0)",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: null }] }, { n: "5" }); }));
  check("validate: empty-string bound throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: "" }] }, { n: "5" }); }));
  check("validate: whitespace-string bound throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: " " }] }, { n: "5" }); }));
  check("validate: boolean bound throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", max: false }] }, { n: "5" }); }));
  check("validate: array bound throws",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: [] }] }, { n: "5" }); }));
  check("validate: minlength null throws (string control)",
        _throws(function () { return b.forms.validate({ fields: [{ type: "text", name: "s", minlength: null }] }, { s: "abc" }); }));
  check("validate: over-long numeric-literal bound throws (length-capped before regex)",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: "1".repeat(50) }] }, { n: "5" }); }));

  // Genuine numeric literals — number and clean numeric string — are fine.
  var okStr = b.forms.validate({ fields: [{ type: "number", name: "n", min: "1", max: "10" }] }, { n: "5" });
  check("validate: numeric-string bounds accepted", okStr.valid === true);
  var okFloat = b.forms.validate({ fields: [{ type: "number", name: "n", min: "-2.5", max: "1e3" }] }, { n: "5" });
  check("validate: signed/decimal/exponent numeric strings accepted", okFloat.valid === true);
}

function testValidateSpecValidatedUpFront() {
  // A malformed field spec is a config error surfaced deterministically at
  // the entry point — the throw must NOT depend on whether the submitted
  // body happens to carry a value that reaches the bound. Each malformed
  // spec throws whether the field is absent, empty, or present.
  function throwsForAllBodies(field, name) {
    var spec = { fields: [field] };
    return _throws(function () { return b.forms.validate(spec, {}); }) &&                 // absent
           _throws(function () { return b.forms.validate(spec, _emptyBody(name)); }) &&    // empty
           _throws(function () { return b.forms.validate(spec, _presentBody(name)); });    // present
  }
  function _emptyBody(name) { var o = {}; o[name] = ""; return o; }
  function _presentBody(name) { var o = {}; o[name] = "5"; return o; }

  check("spec: non-finite min throws regardless of body (absent/empty/present)",
        throwsForAllBodies({ type: "number", name: "n", min: "abc" }, "n"));
  check("spec: non-finite maxlength throws regardless of body",
        throwsForAllBodies({ type: "text", name: "s", maxlength: NaN }, "s"));
  check("spec: string pattern throws regardless of body",
        throwsForAllBodies({ type: "text", name: "p", pattern: "^abc$" }, "p"));
  check("spec: ReDoS-prone pattern throws regardless of body",
        throwsForAllBodies({ type: "text", name: "p", pattern: /(a+)+$/ }, "p"));

  // A well-formed spec with an absent optional value does NOT throw — the
  // up-front pass only rejects malformed specs, never valid ones.
  var okAbsent = b.forms.validate({ fields: [{ type: "number", name: "n", min: 1, max: 10 }, { type: "text", name: "s", pattern: /^[a-z]+$/ }] }, {});
  check("spec: well-formed spec with absent values validates without throwing", okAbsent.valid === true);
}

function testValidateDateTimeBounds() {
  // date / time / datetime-local / month / week controls carry ISO-string
  // min/max bounds. Those are render-only attributes validate() never
  // compares numerically, so a string bound must NOT be treated as a
  // malformed numeric bound — it must not throw at the spec-validation pass.
  var d = b.forms.validate({ fields: [{ type: "date", name: "d", min: "2026-01-01", max: "2026-12-31" }] }, { d: "2026-06-15" });
  check("date: ISO-string min/max does not throw and validates", d.valid === true && d.values.d === "2026-06-15");

  var t = b.forms.validate({ fields: [{ type: "time", name: "t", min: "09:00", max: "17:00" }] }, { t: "12:00" });
  check("time: ISO-string min/max does not throw", t.valid === true);

  var dtlAbsent = b.forms.validate({ fields: [{ type: "datetime-local", name: "dt", min: "2026-01-01T00:00" }] }, {});
  check("datetime-local: ISO-string min with absent value does not throw", dtlAbsent.valid === true);

  var wk = b.forms.validate({ fields: [{ type: "week", name: "w", max: "2026-W52" }] }, { w: "2026-W10" });
  check("week: ISO-string max does not throw", wk.valid === true);

  var mo = b.forms.validate({ fields: [{ type: "month", name: "m", min: "2026-01" }] }, { m: "2026-05" });
  check("month: ISO-string min does not throw", mo.valid === true);

  // The numeric guard is intact for the controls it applies to: a number
  // field with a non-finite min still throws regardless of body.
  check("number: non-finite min still throws (numeric control)",
        _throws(function () { return b.forms.validate({ fields: [{ type: "number", name: "n", min: "abc" }] }, {}); }));
}

function testValidateMiscCoercion() {
  var d = b.forms.validate({ fields: [{ type: "date", name: "d" }] }, { d: "2026-01-15" });
  check("date: string passes through", d.values.d === "2026-01-15");

  var dNum = b.forms.validate({ fields: [{ type: "date", name: "d" }] }, { d: 20260115 });
  check("date: non-string coerced via String()", dNum.values.d === "20260115");

  var tm = b.forms.validate({ fields: [{ type: "time", name: "t" }] }, { t: "13:30" });
  check("time: string passes through", tm.values.t === "13:30");

  var dtl = b.forms.validate({ fields: [{ type: "datetime-local", name: "dt" }] }, { dt: "2026-01-15T13:30" });
  check("datetime-local: string passes through", dtl.values.dt === "2026-01-15T13:30");

  var txtNum = b.forms.validate({ fields: [{ type: "text", name: "x" }] }, { x: 123 });
  check("text: non-string body value coerced via String()", txtNum.values.x === "123");
}

// ============================================================
// validate — email / url
// ============================================================

function testValidateEmail() {
  var ok = b.forms.validate({ fields: [{ type: "email", name: "e" }] }, { e: "ada@example.com" });
  check("email: valid address passes", ok.valid === true && ok.values.e === "ada@example.com");

  var bad = b.forms.validate({ fields: [{ type: "email", name: "e", label: "Email" }] }, { e: "not-an-email" });
  check("email: invalid address → error", bad.valid === false && bad.errors.e === "Email must be a valid email address");

  var over = b.forms.validate({ fields: [{ type: "email", name: "e" }] }, { e: "a".repeat(250) + "@e.com" });
  check("email: over 254 chars → error (length cap before regex)", over.valid === false && typeof over.errors.e === "string");
}

function testValidateUrl() {
  var https = b.forms.validate({ fields: [{ type: "url", name: "u" }] }, { u: "https://example.com/path" });
  check("url: valid https passes (default TLS-only)", https.valid === true);

  var httpDefault = b.forms.validate({ fields: [{ type: "url", name: "u", label: "Site" }] }, { u: "http://example.com" });
  check("url: cleartext http rejected by default", httpDefault.valid === false && httpDefault.errors.u === "Site must be a valid URL");

  var httpOptIn = b.forms.validate({ fields: [{ type: "url", name: "u", allowHttp: true }] }, { u: "http://example.com" });
  check("url: cleartext http admitted with allowHttp:true", httpOptIn.valid === true);

  var invalid = b.forms.validate({ fields: [{ type: "url", name: "u" }] }, { u: "notaurl" });
  check("url: unparseable value → error", invalid.valid === false && typeof invalid.errors.u === "string");

  var over = b.forms.validate({ fields: [{ type: "url", name: "u" }] }, { u: "https://e.com/" + "a".repeat(8200) });
  check("url: over 8 KiB → error without engaging the parser", over.valid === false && typeof over.errors.u === "string");
}

// ============================================================
// validate — length, pattern, enum
// ============================================================

function testValidateLengthBounds() {
  var short = b.forms.validate({ fields: [{ type: "text", name: "u", minlength: 5, label: "User" }] }, { u: "abc" });
  check("string: below minlength → error", short.valid === false && typeof short.errors.u === "string");

  var long = b.forms.validate({ fields: [{ type: "text", name: "u", maxlength: 3 }] }, { u: "abcdef" });
  check("string: above maxlength → error", long.valid === false && typeof long.errors.u === "string");

  var ok = b.forms.validate({ fields: [{ type: "text", name: "u", minlength: 2, maxlength: 8 }] }, { u: "abcd" });
  check("string: within length bounds → valid", ok.valid === true);
}

function testValidatePattern() {
  var ok = b.forms.validate({ fields: [{ type: "text", name: "code", pattern: /^[a-z]+$/ }] }, { code: "abc" });
  check("pattern: RegExp match → valid", ok.valid === true);

  var bad = b.forms.validate({ fields: [{ type: "text", name: "code", pattern: /^[a-z]+$/, label: "Code" }] }, { code: "ABC123" });
  check("pattern: RegExp mismatch → error (label in default message)", bad.valid === false && bad.errors.code === "Code has an invalid format");

  var badNoLabel = b.forms.validate({ fields: [{ type: "text", name: "code", pattern: /^[a-z]+$/ }] }, { code: "ABC123" });
  check("pattern: RegExp mismatch without label falls back to field name", badNoLabel.valid === false && badNoLabel.errors.code === "code has an invalid format");

  var custom = b.forms.validate({ fields: [{ type: "text", name: "code", pattern: /^[a-z]+$/, errorMessages: { pattern: "letters only" } }] }, { code: "9" });
  check("pattern: custom errorMessages.pattern used", custom.valid === false && custom.errors.code === "letters only");
}

function testValidateEnum() {
  var okSel = b.forms.validate({ fields: [{ type: "select", name: "s", options: [{ value: "a" }, { value: "b" }] }] }, { s: "a" });
  check("select: value within options → valid", okSel.valid === true && okSel.values.s === "a");

  var badSel = b.forms.validate({ fields: [{ type: "select", name: "s", label: "Choice", options: [{ value: "a" }, { value: "b" }] }] }, { s: "c" });
  check("select: value outside options → error", badSel.valid === false && badSel.errors.s === "Choice has an invalid value");

  var okRadio = b.forms.validate({ fields: [{ type: "radio", name: "r", options: [{ value: "x" }, { value: "y" }] }] }, { r: "y" });
  check("radio: value within options → valid", okRadio.valid === true);

  var badRadio = b.forms.validate({ fields: [{ type: "radio", name: "r", options: [{ value: "x" }] }] }, { r: "z" });
  check("radio: value outside options → error", badRadio.valid === false && typeof badRadio.errors.r === "string");

  var noOpts = b.forms.validate({ fields: [{ type: "select", name: "s" }] }, { s: "anything" });
  check("select: no options array → enum check skipped (valid)", noOpts.valid === true && noOpts.values.s === "anything");
}

// ============================================================
// validate — full submission + shared-spec render/validate round-trip
// ============================================================

function testValidateEndToEnd() {
  var spec = { fields: [
    { type: "email",    name: "email",    required: true },
    { type: "password", name: "password", required: true, minlength: 8 },
    { type: "number",   name: "age",      min: 18, max: 120 },
    { type: "checkbox", name: "tos" },
    { type: "submit",   name: "submit" },
  ] };

  var good = b.forms.validate(spec, { email: "ada@example.com", password: "hunter2!!", age: "30", tos: "on" });
  check("e2e: fully valid submission", good.valid === true && Object.keys(good.errors).length === 0);
  check("e2e: coerced values", good.values.email === "ada@example.com" && good.values.age === 30 && good.values.tos === true);
  check("e2e: submit field excluded from values", Object.prototype.hasOwnProperty.call(good.values, "submit") === false);

  var bad = b.forms.validate(spec, { email: "nope", password: "short", age: "5" });
  check("e2e: multiple errors collected",
        bad.valid === false && !!bad.errors.email && !!bad.errors.password && !!bad.errors.age);
  check("e2e: unchecked checkbox coerces to false", bad.values.tos === false);
}

function testSharedSpecRoundTrip() {
  var spec = {
    action:    "/signup",
    method:    "POST",
    csrfToken: b.forms.generateCsrfToken(),
    fields: [
      { type: "email", name: "email", label: "Email", required: true },
      { type: "text",  name: "user",  minlength: 3, maxlength: 20 },
      { type: "submit", name: "go", value: "Sign up" },
    ],
  };
  var html = b.forms.render(spec);
  check("shared-spec: render emits form + csrf + fields",
        html.indexOf("<form ") === 0 && html.indexOf('name="_csrf"') !== -1 && html.indexOf('type="email"') !== -1);
  var res = b.forms.validate(spec, { email: "ada@example.com", user: "ada" });
  check("shared-spec: the same spec validates a matching body", res.valid === true);
}

// ============================================================

async function run() {
  testGenerateCsrfToken();
  testVerifyCsrfToken();
  testEscapeAttribute();

  testRenderThrows();
  testRenderFormAttrs();
  testRenderCsrfGating();
  testRenderInputAttrs();
  testRenderInputValuePresence();
  testRenderTextarea();
  testRenderSelect();
  testRenderFieldTypesAndLabels();
  testRenderSubmitButton();

  testValidateThrows();
  testValidateRequiredAndShape();
  testValidateSkips();
  testValidateCheckboxCoercion();
  testValidateRequiredCheckbox();
  testValidateNumberCoercionAndBounds();
  testValidateNumericBoundConfig();
  testValidateSpecValidatedUpFront();
  testValidateDateTimeBounds();
  testValidateMiscCoercion();
  testValidateEmail();
  testValidateUrl();
  testValidateLengthBounds();
  testValidatePattern();
  testValidateEnum();
  testValidateEndToEnd();
  testSharedSpecRoundTrip();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
