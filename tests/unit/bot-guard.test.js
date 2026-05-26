"use strict";
/**
 * bot-guard wrapper (middleware/bot-guard.js) — page-nav fingerprint gate.
 *
 * Regression: a browser reaching the app over a plain-HTTP non-localhost
 * origin (Umbrel app at http://<device>.local:3080, LAN / *.local reverse
 * proxies) omits Sec-Fetch-* entirely — those headers are sent only to a
 * secure context per the Fetch Metadata spec. A missing Sec-Fetch-Mode must
 * therefore NOT be read as a bot signal: doing so 403'd real users opening
 * the landing page. Genuine bots stay blocked by the missing-Accept-Language
 * and User-Agent heuristics.
 */
const { describe, it } = require("node:test");
const assert = require("node:assert");

var b = require("../../lib/vendor/blamejs");
var botGuard = require("../../middleware/bot-guard");

// Drive the middleware once; return whether it fell through to the app
// (next() called) or terminated the chain with a response.
function dispatch(headers) {
  var req = b.testing.mockReq({ method: "GET", pathname: "/", headers: headers });
  var res = b.testing.mockRes();
  var nexted = false;
  botGuard(req, res, function () { nexted = true; });
  var cap = res._captured();
  return { nexted: nexted, status: cap.status, body: cap.body, ended: cap.ended };
}

var CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

describe("bot-guard wrapper", function () {
  it("lets a browser through on a plain-HTTP .local origin with no Sec-Fetch-Mode (Umbrel)", function () {
    var r = dispatch({
      "user-agent": CHROME,
      "accept-language": "en-US,en;q=0.9",
      "host": "umbrel-dev.local:3080",
    });
    assert.strictEqual(r.nexted, true, "Umbrel-proxied browser must reach the app, not 403");
    assert.notStrictEqual(r.status, 403);
  });

  it("lets a secure-context browser through (Sec-Fetch-Mode present)", function () {
    var r = dispatch({
      "user-agent": CHROME,
      "accept-language": "en-US,en;q=0.9",
      "sec-fetch-mode": "navigate",
      "host": "localhost:3000",
    });
    assert.strictEqual(r.nexted, true);
  });

  it("still blocks a known automation UA", function () {
    var r = dispatch({ "user-agent": "curl/8.4.0", "host": "umbrel-dev.local:3080" });
    assert.strictEqual(r.nexted, false);
    assert.strictEqual(r.status, 403);
    assert.strictEqual(r.body, "Forbidden");
  });

  it("still blocks a request missing Accept-Language", function () {
    var r = dispatch({ "user-agent": CHROME, "host": "umbrel-dev.local:3080" });
    assert.strictEqual(r.nexted, false);
    assert.strictEqual(r.status, 403);
  });
});
