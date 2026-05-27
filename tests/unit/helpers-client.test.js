"use strict";
/**
 * public/js/helpers.js — Helpers.copyText() and Helpers.uuid().
 *
 * Both wrap browser APIs that exist only in a secure context:
 *   - navigator.clipboard.writeText  (async Clipboard API)
 *   - crypto.randomUUID
 * Over plain HTTP at a non-localhost origin those are undefined, so the
 * helpers must fall back (execCommand('copy') / crypto.getRandomValues)
 * instead of throwing "Cannot read properties of undefined".
 */
const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

var src = fs.readFileSync(path.join(__dirname, "../../public/js/helpers.js"), "utf8");

function loadHelpers(globals) {
  var sandbox = Object.assign({ window: {} }, globals);
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  return sandbox.window.Helpers;
}

var V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("Helpers.uuid()", function () {
  it("uses crypto.randomUUID when available (secure context)", function () {
    var h = loadHelpers({
      window: { crypto: { randomUUID: function () { return "11111111-1111-4111-8111-111111111111"; } } },
      crypto: { randomUUID: function () { return "11111111-1111-4111-8111-111111111111"; } },
    });
    assert.strictEqual(h.uuid(), "11111111-1111-4111-8111-111111111111");
  });

  it("falls back to getRandomValues when randomUUID is absent (plain HTTP) and yields a valid v4", function () {
    var h = loadHelpers({
      window: { crypto: {} },
      crypto: { getRandomValues: function (arr) { for (var i = 0; i < arr.length; i++) arr[i] = (i * 37 + 11) & 0xff; return arr; } },
    });
    var u = h.uuid();
    assert.match(u, V4, "expected RFC 4122 v4 shape, got " + u);
  });
});

describe("Helpers.copyText()", function () {
  it("uses navigator.clipboard.writeText when available", function () {
    var called = null;
    var h = loadHelpers({
      window: {},
      navigator: { clipboard: { writeText: function (t) { called = t; return Promise.resolve(); } } },
    });
    return h.copyText("hello").then(function () {
      assert.strictEqual(called, "hello");
    });
  });

  it("falls back to execCommand('copy') when the Clipboard API is absent (plain HTTP)", function () {
    var copied = false;
    var appended = 0;
    var fakeEl = { value: "", setAttribute: function () {}, style: {}, select: function () {} };
    var h = loadHelpers({
      window: {},
      navigator: {},   // no clipboard
      document: {
        createElement: function () { return fakeEl; },
        body: { appendChild: function () { appended++; }, removeChild: function () { appended--; } },
        execCommand: function (cmd) { copied = (cmd === "copy"); return true; },
      },
    });
    return h.copyText("payload").then(function () {
      assert.strictEqual(fakeEl.value, "payload");
      assert.strictEqual(copied, true);
      assert.strictEqual(appended, 0, "temp textarea must be cleaned up");
    });
  });
});
