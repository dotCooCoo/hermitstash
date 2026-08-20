// HSTS is emitted for the request that arrived over TLS, and only that one.
//
// It used to be gated on `config.rpOrigin.startsWith("https")`, which disagreed
// with the rule the comment above it stated — "Sent only over HTTPS". With an
// https rpOrigin the header went out on plain-HTTP responses too (RFC 6797 §8.1
// has the user agent ignore those, so it was inert rather than harmful), and
// with a non-https rpOrigin a visitor arriving over real TLS got no HSTS at all.
// That second case is the one that cost something, and it is the case a
// deployment answering on more than one hostname actually hits.
//
// The hand-rolled header is gone. b.middleware.securityHeaders already emits
// HSTS gated on the peer-resolved request scheme, and its default value is the
// same posture HS was writing by hand, so the middleware is configured with a
// protocolResolver instead of a second implementation. These tests pin the
// header's value as well as its presence: dropping to the framework default
// must not quietly change max-age, includeSubDomains or preload.

require("../helpers/isolate-db");
const { describe, it } = require("node:test");
const assert = require("node:assert");

process.env.RP_ORIGIN = "https://files.example.com";
process.env.TRUST_PROXY = "10.0.0.0/8";

var securityHeaders = require("../../middleware/security-headers");

var EXPECTED = "max-age=63072000; includeSubDomains; preload";

// Run the real middleware and report the Strict-Transport-Security it set.
function hstsFor(opts) {
  var headers = {};
  var req = {
    headers: opts.headers || {},
    socket: { encrypted: !!opts.tls, remoteAddress: opts.peer || "203.0.113.9" },
    pathname: "/",
    method: "GET",
  };
  var res = {
    statusCode: 200,
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
    removeHeader: function (k) { delete headers[k]; },
    writeHead: function () { return res; },
    end: function () {},
  };
  securityHeaders(req, res, function () {});
  return headers["Strict-Transport-Security"];
}

describe("HSTS follows the request scheme, not the configured origin", function () {

  it("emits on a direct TLS request", function () {
    assert.strictEqual(hstsFor({ tls: true }), EXPECTED);
  });

  it("emits for a trusted proxy's forwarded https", function () {
    assert.strictEqual(
      hstsFor({ headers: { "x-forwarded-proto": "https" }, peer: "10.0.0.5" }),
      EXPECTED);
  });

  it("does not emit on plain HTTP, even with an https rpOrigin", function () {
    // RP_ORIGIN is https for this whole file, so this case is exactly the one
    // the old gate got wrong.
    assert.strictEqual(hstsFor({}), undefined);
  });

  it("does not emit for a forged X-Forwarded-Proto from an untrusted peer", function () {
    // Otherwise any caller could make the server assert an HTTPS-only policy
    // for a hostname on their behalf.
    assert.strictEqual(
      hstsFor({ headers: { "x-forwarded-proto": "https" }, peer: "203.0.113.9" }),
      undefined);
  });

  it("does not emit when a trusted proxy forwards http", function () {
    assert.strictEqual(
      hstsFor({ headers: { "x-forwarded-proto": "http" }, peer: "10.0.0.5" }),
      undefined);
  });

  it("keeps the 2-year preload-eligible posture", function () {
    // Pinned against the framework default silently changing under a vendor
    // bump. hstspreload.org requires at least one year; submission requires two,
    // plus includeSubDomains and preload.
    var v = hstsFor({ tls: true });
    assert.match(v, /max-age=63072000/, "2-year max-age");
    assert.match(v, /includeSubDomains/);
    assert.match(v, /preload/);
  });
});
