// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.earlyHints — RFC 8297 103 Early Hints helper.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockRes() {
  var calls = [];
  return {
    writeEarlyHints: function (h) { calls.push(h); },
    _calls: function () { return calls; },
  };
}

function testSurface() {
  check("earlyHints.send is fn", typeof b.earlyHints.send === "function");
  check("REFUSED_HEADERS is array", Array.isArray(b.earlyHints.REFUSED_HEADERS));
  check("EarlyHintsError is a constructor",
        typeof b.earlyHints.EarlyHintsError === "function");
}

function testHappyPath() {
  var res = _mockRes();
  var ok = b.earlyHints.send(res, {
    link: [
      "</style.css>; rel=preload; as=style",
      "<https://cdn.example.com>; rel=preconnect",
    ],
  });
  check("send: returns true on success", ok === true);
  var c = res._calls();
  check("send: writeEarlyHints called once",  c.length === 1);
  check("send: link headers passed through",
        Array.isArray(c[0].link) && c[0].link.length === 2);
}

function testSingleStringLink() {
  var res = _mockRes();
  b.earlyHints.send(res, { link: "</app.js>; rel=preload; as=script" });
  check("send: single string link wraps to array",
        Array.isArray(res._calls()[0].link) && res._calls()[0].link.length === 1);
}

function testRefusesBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("send: bad res",
             function () { b.earlyHints.send(null, { link: "<x>; rel=preload" }); }, "early-hints/bad-res");
  var res = _mockRes();
  expectCode("send: missing opts",
             function () { b.earlyHints.send(res); }, "early-hints/bad-opts");
  expectCode("send: missing link",
             function () { b.earlyHints.send(res, {}); }, "early-hints/no-link");
  expectCode("send: empty link array",
             function () { b.earlyHints.send(res, { link: [] }); }, "early-hints/no-link");
  expectCode("send: link without rel",
             function () { b.earlyHints.send(res, { link: "</x.css>" }); }, "early-hints/bad-link");
  expectCode("send: link with unknown rel",
             function () { b.earlyHints.send(res, { link: "</x.css>; rel=icon" }); }, "early-hints/bad-link");
  expectCode("send: link without angle-bracketed URI",
             function () { b.earlyHints.send(res, { link: "/x.css; rel=preload" }); }, "early-hints/bad-link");
  expectCode("send: refused header (set-cookie)",
             function () { b.earlyHints.send(res, { link: "<x>; rel=preload", "set-cookie": "a=1" }); }, "early-hints/refused-header");
  expectCode("send: refused header (authorization)",
             function () { b.earlyHints.send(res, { link: "<x>; rel=preload", authorization: "Bearer x" }); }, "early-hints/refused-header");
  expectCode("send: refused header (content-length)",
             function () { b.earlyHints.send(res, { link: "<x>; rel=preload", "content-length": "100" }); }, "early-hints/refused-header");

  var bigLink = "<" + new Array(5000).join("x") + ">; rel=preload";
  expectCode("send: huge link refused",
             function () { b.earlyHints.send(res, { link: bigLink }); }, "early-hints/bad-link");
}

function testNoWriteEarlyHintsFallback() {
  // HTTP/1.0 or unmocked res: silent no-op, returns false.
  var noFn = {};
  check("send: returns false when writeEarlyHints missing",
        b.earlyHints.send(noFn, { link: "<x>; rel=preload" }) === false);
}

function testCaseVariantLinkRefused() {
  // Pre-v0.8.89 bug: supplying both `link` (lowercase) AND `Link`
  // (capital) bypassed validation. opts.link got validated; opts.Link
  // got lowercased in the trailing header loop and overwrote
  // headers.link with the unvalidated value. Now the case-variant
  // collision refuses explicitly.
  var res = _mockRes();
  var threw = null;
  try {
    b.earlyHints.send(res, {
      link: "</a.css>; rel=preload; as=style",       // would validate
      Link: "garbage no rel param",                  // would have bypassed validation
    });
  } catch (e) { threw = e; }
  check("send: case-variant Link refused",
        threw && /duplicate-header/.test(threw.code || ""));

  // Also: a single `Link` (capital-only) variant still gets the
  // normal validation path applied via canonical-name lookup.
  var res2 = _mockRes();
  var ok = b.earlyHints.send(res2, { Link: "</a.css>; rel=preload; as=style" });
  check("send: capital-Link only validates + sends",
        ok === true &&
        Array.isArray(res2._calls()[0].link) &&
        res2._calls()[0].link[0].indexOf("</a.css>") === 0);

  // And: capital-Link with bad content refuses (validation runs).
  var res3 = _mockRes();
  var threw3 = null;
  try { b.earlyHints.send(res3, { Link: "no-rel-param" }); }
  catch (e) { threw3 = e; }
  check("send: capital-Link with bad link refuses",
        threw3 && /bad-link/.test(threw3.code || ""));
}

function testKnownRelations() {
  var res = _mockRes();
  var relations = ["preload", "preconnect", "prefetch", "dns-prefetch",
                   "modulepreload", "prerender", "next", "prev"];
  for (var i = 0; i < relations.length; i += 1) {
    var ok = b.earlyHints.send(res, { link: "<x>; rel=" + relations[i] });
    check("send: rel=" + relations[i] + " accepted", ok === true);
  }
}

async function run() {
  testSurface();
  testHappyPath();
  testSingleStringLink();
  testRefusesBadShape();
  testNoWriteEarlyHintsFallback();
  testCaseVariantLinkRefused();
  testKnownRelations();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
