"use strict";
/**
 * public/js/webauthn-helpers.js — WebAuthnHelpers.supported() guard.
 *
 * Regression: passkey ceremonies (navigator.credentials.create/get) are only
 * available in a secure context. Over plain HTTP at a non-localhost hostname
 * (LAN host, reverse-proxy deployment without TLS) the API is absent and a
 * naive call throws "Cannot read properties of undefined (reading 'create')".
 * supported() must return false in every non-secure-context shape so callers
 * surface UNSUPPORTED_MSG and hide the passkey UI instead of crashing.
 */
const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

var src = fs.readFileSync(path.join(__dirname, "../../public/js/webauthn-helpers.js"), "utf8");

// Load the browser IIFE into an isolated context whose globals (window,
// navigator, PublicKeyCredential) we control, then return WebAuthnHelpers.
function loadHelpers(globals) {
  var sandbox = Object.assign({ window: {} }, globals);
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return sandbox.window.WebAuthnHelpers;
}

var FULL_CREDS = { create: function () {}, get: function () {} };

describe("WebAuthnHelpers.supported()", function () {
  it("true in a secure context with the full WebAuthn API", function () {
    var h = loadHelpers({
      window: { isSecureContext: true, PublicKeyCredential: function () {} },
      navigator: { credentials: FULL_CREDS },
    });
    assert.strictEqual(h.supported(), true);
  });

  it("false on a non-secure context (plain HTTP / .local — the Umbrel case)", function () {
    var h = loadHelpers({
      window: { isSecureContext: false, PublicKeyCredential: function () {} },
      navigator: { credentials: FULL_CREDS },
    });
    assert.strictEqual(h.supported(), false);
  });

  it("false when PublicKeyCredential is absent", function () {
    var h = loadHelpers({
      window: { isSecureContext: true },
      navigator: { credentials: FULL_CREDS },
    });
    assert.strictEqual(h.supported(), false);
  });

  it("false when navigator.credentials is undefined (no .create to read)", function () {
    var h = loadHelpers({
      window: { isSecureContext: true, PublicKeyCredential: function () {} },
      navigator: {},
    });
    assert.strictEqual(h.supported(), false);
  });

  it("exposes a user-facing unsupported message", function () {
    var h = loadHelpers({ window: {}, navigator: {} });
    assert.match(h.UNSUPPORTED_MSG, /HTTPS/);
  });
});
