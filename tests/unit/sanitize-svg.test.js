const { describe, it } = require("node:test");
const assert = require("node:assert");

var { sanitizeSvg } = require("../../lib/sanitize-svg");

describe("sanitize-svg", function () {
  describe("dangerous tag removal", function () {
    it("removes <script> tags", function () {
      var input = '<svg><script>alert("xss")</script><circle r="5"/></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("<script"), "should remove script tag");
      assert.ok(result.includes("<circle"), "should preserve safe elements");
    });

    it("removes <iframe> tags", function () {
      var input = '<svg><iframe src="http://evil.com"></iframe></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("<iframe"), "should remove iframe tag");
    });

    it("removes <object> tags", function () {
      var input = '<svg><object data="evil.swf"></object></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("<object"), "should remove object tag");
    });

    it("removes <embed> tags", function () {
      var input = '<svg><embed src="evil.swf"></embed></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("<embed"), "should remove embed tag");
    });

    it("removes <foreignObject> tags", function () {
      var input = '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("<foreignObject"), "should remove foreignObject tag");
    });
  });

  describe("event handler removal", function () {
    it("removes onclick handler", function () {
      var input = '<svg><rect onclick="alert(1)" width="100" height="100"/></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("onclick"), "should remove onclick");
      assert.ok(result.includes("width"), "should preserve other attributes");
    });

    it("removes onload handler", function () {
      var input = '<svg onload="alert(1)"><circle r="5"/></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("onload"), "should remove onload");
    });
  });

  describe("javascript URI removal", function () {
    it("removes href=\"javascript:\" links", function () {
      var input = '<svg><a href="javascript:alert(1)"><text>click</text></a></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("javascript:"), "should remove javascript: URI");
    });

    it("removes xlink:href=\"javascript:\" links", function () {
      var input = '<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("javascript:"), "should remove xlink javascript: URI");
    });
  });

  describe("data URI removal", function () {
    it("removes data:text/html URIs", function () {
      var input = '<svg><a href="data:text/html,<script>alert(1)</script>"><text>x</text></a></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("data:text/html"), "should remove data:text/html URI");
    });

    it("removes data:text/javascript URIs", function () {
      var input = '<svg><a href="data:text/javascript,alert(1)"><text>x</text></a></svg>';
      var result = sanitizeSvg(input);
      assert.ok(!result.includes("data:text/javascript"), "should remove data:text/javascript URI");
    });
  });

  describe("safe element preservation", function () {
    it("preserves safe SVG elements", function () {
      var input = '<svg><circle cx="50" cy="50" r="40"/><rect x="10" y="10" width="80" height="80"/><path d="M10 10"/><text x="0" y="15">Hello</text><g id="group"><line x1="0" y1="0" x2="100" y2="100"/></g></svg>';
      var result = sanitizeSvg(input);
      assert.ok(result.includes("<circle"), "should preserve circle");
      assert.ok(result.includes("<rect"), "should preserve rect");
      assert.ok(result.includes("<path"), "should preserve path");
      assert.ok(result.includes("<text"), "should preserve text");
      assert.ok(result.includes("<g"), "should preserve g");
    });
  });

  describe("edge cases", function () {
    it("returns empty string for null input", function () {
      assert.strictEqual(sanitizeSvg(null), "");
    });

    it("returns empty string for non-string input", function () {
      assert.strictEqual(sanitizeSvg(42), "");
    });

    it("returns empty string for undefined input", function () {
      assert.strictEqual(sanitizeSvg(undefined), "");
    });
  });
});
