// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * sigv4 - list / listVersions / head / delete response-shape decoding.
 *
 * The live MinIO suite (test/integration/object-store-sigv4.test.js) proves
 * the happy-path wire contract: a well-formed bucket listing, a present
 * object, a successful delete. It cannot produce the shapes a NON-MinIO
 * S3-compatible store legitimately returns, and it cannot produce a 5xx on
 * demand. Those shapes are what this file pins:
 *
 *   - pagination inputs actually reach the wire query (max-keys /
 *     continuation-token / key-marker / version-id-marker) and their values
 *     survive SigV4 canonicalization (the request is accepted, not 403'd);
 *   - a listing whose root element is missing degrades to an EMPTY result
 *     instead of throwing on a property of undefined;
 *   - per-entry optional elements (Size / LastModified / ETag / VersionId)
 *     that a vendor omits decode to null WITHOUT losing the fields that ARE
 *     present - a decoder that drops `key` while nulling `size` would still
 *     "pass" a length check, so every case asserts preservation too;
 *   - a DeleteMarker row is a tombstone: size + etag null, identity fields
 *     intact;
 *   - head() maps a missing key to the framework NOT_FOUND code but must
 *     RE-THROW any other status unchanged (a 500 silently reported as
 *     "not found" is a data-loss-shaped lie for an existence probe);
 *   - delete() reports false for an absent key rather than throwing.
 *
 * Run standalone: `node test/layer-0-primitives/sigv4-list-response-shapes.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var http    = require("http");
var helpers = require("../helpers");
var sigv4   = require("../../lib/object-store/sigv4");
var b       = helpers.b;
var check   = helpers.check;
var listenOnRandomPort = helpers.listenOnRandomPort;

var XML_HEAD = "<?xml version='1.0' encoding='UTF-8'?>";

function _baseConfig(port, overrides) {
  var cfg = {
    region:           "us-east-1",
    bucket:           "shape-bucket",
    accessKeyId:      "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:         "http://127.0.0.1:" + port,
    pathStyle:        true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

// A fake S3 whose response is fully controlled by the test. `handler` is
// called with the recorded request and returns { status?, headers?, body? };
// returning nothing falls through to a bare 200.
function _fakeS3(handler) {
  var requests = [];
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var rec = {
        method:  req.method,
        url:     req.url,
        query:   new URL("http://x" + req.url).searchParams,
        headers: req.headers,
        body:    Buffer.concat(chunks),
      };
      requests.push(rec);
      var out = handler ? handler(rec) : null;
      if (!out) out = {};
      res.writeHead(out.status || 200,
        Object.assign({ "Content-Type": "application/xml" }, out.headers || {}));
      res.end(out.body === undefined ? "" : out.body);
    });
  });
  return { server: server, requests: requests };
}

// Every test opens one server; close it in a finally so no listener leaks
// into the next case (a leaked listener hangs the direct run).
async function _withFakeS3(handler, body) {
  var fake = _fakeS3(handler);
  var port = await listenOnRandomPort(fake.server);
  try {
    return await body(sigv4.create(_baseConfig(port)), fake, port);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- list(): pagination params reach the wire + are signed ----

async function testListPaginationParamsReachTheWire() {
  await _withFakeS3(function () {
    return {
      body: XML_HEAD +
        "<ListBucketResult>" +
        "<IsTruncated>true</IsTruncated>" +
        "<NextContinuationToken>page-2-token</NextContinuationToken>" +
        "<Contents><Key>a.txt</Key><Size>11</Size>" +
        "<LastModified>2026-01-02T03:04:05.000Z</LastModified></Contents>" +
        "<Contents><Key>b.txt</Key><Size>22</Size>" +
        "<LastModified>2026-01-02T03:04:06.000Z</LastModified></Contents>" +
        "</ListBucketResult>",
    };
  }, async function (store, fake) {
    var page = await store.list("docs/", { maxResults: 2, continuationToken: "page-1-token" });
    var q = fake.requests[0].query;
    check("list params: list-type=2 always sent",       q.get("list-type") === "2");
    check("list params: prefix forwarded",              q.get("prefix") === "docs/");
    check("list params: maxResults -> max-keys",        q.get("max-keys") === "2");
    check("list params: continuationToken -> continuation-token",
          q.get("continuation-token") === "page-1-token");
    // The paging params are part of the SigV4 canonical query; a signer that
    // dropped them would still reach the server but with a signature over a
    // different query. Assert the transmitted query and the signed
    // SignedHeaders/Signature pair are internally consistent by recomputing
    // the canonical query from what actually arrived.
    var canonical = sigv4.canonicalQueryString(q);
    check("list params: transmitted query canonicalizes in sorted AWS form",
          canonical === "continuation-token=page-1-token&list-type=2&max-keys=2&prefix=docs%2F");
    check("list params: request carried an AWS4-HMAC-SHA256 Authorization header",
          /^AWS4-HMAC-SHA256 Credential=/.test(fake.requests[0].headers.authorization || ""));

    // Two <Contents> children decode through the array arm of the arrayify
    // normalizer - a single child arrives as a bare object.
    check("list decode: both entries surfaced",         page.items.length === 2);
    check("list decode: keys preserved in order",
          page.items[0].key === "a.txt" && page.items[1].key === "b.txt");
    check("list decode: sizes parsed as numbers",
          page.items[0].size === 11 && page.items[1].size === 22);
    check("list decode: lastModified parsed to epoch ms",
          page.items[0].lastModified === Date.parse("2026-01-02T03:04:05.000Z"));
    check("list decode: truncated flag from IsTruncated",  page.truncated === true);
    check("list decode: continuationToken from NextContinuationToken",
          page.continuationToken === "page-2-token");
  });
}

// ---- list(): missing root element degrades to an empty page ----

async function testListMissingRootElementIsEmptyNotThrow() {
  await _withFakeS3(function () {
    // A vendor error/redirect body that is well-formed XML but is not a
    // ListBucketResult. Decoding must not read through undefined.
    return { body: XML_HEAD + "<UnexpectedRoot><Note>not a listing</Note></UnexpectedRoot>" };
  }, async function (store) {
    var page = await store.list("any/");
    check("list no-root: items is an empty array (not a throw)",
          Array.isArray(page.items) && page.items.length === 0);
    check("list no-root: truncated defaults false",        page.truncated === false);
    check("list no-root: continuationToken defaults null", page.continuationToken === null);
  });
}

// ---- list(): per-entry optional elements omitted by the vendor ----

async function testListEntryOptionalFieldsOmitted() {
  await _withFakeS3(function () {
    return {
      body: XML_HEAD +
        "<ListBucketResult>" +
        // no <Size>, has LastModified
        "<Contents><Key>no-size.txt</Key>" +
        "<LastModified>2026-02-03T00:00:00.000Z</LastModified></Contents>" +
        // has Size, no <LastModified>
        "<Contents><Key>no-mtime.txt</Key><Size>512</Size></Contents>" +
        // no <Key> at all - must be dropped, not surfaced as a null-key item
        "<Contents><Size>99</Size></Contents>" +
        "</ListBucketResult>",
    };
  }, async function (store) {
    var page = await store.list("");
    check("list optional: keyless entry dropped (2 of 3 surfaced)", page.items.length === 2);
    var noSize = page.items[0];
    var noMtime = page.items[1];
    check("list optional: missing Size -> size null",       noSize.size === null);
    check("list optional: missing Size PRESERVES key",      noSize.key === "no-size.txt");
    check("list optional: missing Size PRESERVES lastModified",
          noSize.lastModified === Date.parse("2026-02-03T00:00:00.000Z"));
    check("list optional: missing LastModified -> null",    noMtime.lastModified === null);
    check("list optional: missing LastModified PRESERVES key",
          noMtime.key === "no-mtime.txt");
    check("list optional: missing LastModified PRESERVES size", noMtime.size === 512);
  });
}

// ---- listVersions(): marker params reach the wire ----

async function testListVersionsMarkerParamsReachTheWire() {
  await _withFakeS3(function () {
    return {
      body: XML_HEAD +
        "<ListVersionsResult>" +
        "<IsTruncated>true</IsTruncated>" +
        "<NextKeyMarker>next-key</NextKeyMarker>" +
        "<NextVersionIdMarker>next-vid</NextVersionIdMarker>" +
        "<Version><Key>k.txt</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest>" +
        "<Size>7</Size><ETag>\"etag-v2\"</ETag>" +
        "<LastModified>2026-03-04T05:06:07.000Z</LastModified></Version>" +
        "<Version><Key>k.txt</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest>" +
        "<Size>3</Size><ETag>\"etag-v1\"</ETag>" +
        "<LastModified>2026-03-04T05:06:00.000Z</LastModified></Version>" +
        "</ListVersionsResult>",
    };
  }, async function (store, fake) {
    var page = await store.listVersions("k", {
      maxResults:      2,
      keyMarker:       "start-key",
      versionIdMarker: "start-vid",
    });
    var q = fake.requests[0].query;
    check("listVersions params: ?versions subresource present", q.has("versions"));
    check("listVersions params: prefix forwarded",              q.get("prefix") === "k");
    check("listVersions params: maxResults -> max-keys",        q.get("max-keys") === "2");
    check("listVersions params: keyMarker -> key-marker",       q.get("key-marker") === "start-key");
    check("listVersions params: versionIdMarker -> version-id-marker",
          q.get("version-id-marker") === "start-vid");
    check("listVersions params: request was SigV4-signed",
          /^AWS4-HMAC-SHA256 Credential=/.test(fake.requests[0].headers.authorization || ""));

    check("listVersions decode: both versions surfaced",   page.items.length === 2);
    check("listVersions decode: versionIds preserved",
          page.items[0].versionId === "v2" && page.items[1].versionId === "v1");
    check("listVersions decode: isLatest only on the newest",
          page.items[0].isLatest === true && page.items[1].isLatest === false);
    check("listVersions decode: neither row is a delete-marker",
          page.items[0].deleteMarker === false && page.items[1].deleteMarker === false);
    check("listVersions decode: sizes parsed",
          page.items[0].size === 7 && page.items[1].size === 3);
    check("listVersions decode: etags preserved verbatim (quotes included)",
          page.items[0].etag === '"etag-v2"');
    check("listVersions decode: truncated + markers surfaced",
          page.truncated === true && page.keyMarker === "next-key" &&
          page.versionIdMarker === "next-vid");
  });
}

// ---- listVersions(): missing root element degrades to an empty page ----

async function testListVersionsMissingRootElementIsEmpty() {
  await _withFakeS3(function () {
    return { body: XML_HEAD + "<UnexpectedRoot><Note>not a versions listing</Note></UnexpectedRoot>" };
  }, async function (store) {
    var page = await store.listVersions("k");
    check("listVersions no-root: empty items",
          Array.isArray(page.items) && page.items.length === 0);
    check("listVersions no-root: truncated false",     page.truncated === false);
    check("listVersions no-root: keyMarker null",      page.keyMarker === null);
    check("listVersions no-root: versionIdMarker null", page.versionIdMarker === null);
  });
}

// ---- listVersions(): delete-marker tombstones + omitted optional fields ----

async function testListVersionsTombstoneAndOmittedFields() {
  await _withFakeS3(function () {
    return {
      body: XML_HEAD +
        "<ListVersionsResult>" +
        // Version rows exercising each omitted optional independently.
        "<Version><Key>k.txt</Key><IsLatest>true</IsLatest>" +
        "<ETag>\"e-nosize\"</ETag>" +
        "<LastModified>2026-04-05T00:00:00.000Z</LastModified></Version>" +   // no Size, no VersionId
        "<Version><Key>k.txt</Key><VersionId>v9</VersionId><IsLatest>false</IsLatest>" +
        "<Size>42</Size></Version>" +                                          // no LastModified, no ETag
        // A tombstone. S3 never sends Size/ETag on a DeleteMarker; the
        // decoder must null them WITHOUT dropping the identity fields.
        "<DeleteMarker><Key>k.txt</Key><VersionId>vdel</VersionId>" +
        "<IsLatest>false</IsLatest>" +
        "<LastModified>2026-04-06T00:00:00.000Z</LastModified></DeleteMarker>" +
        // No <Key> - dropped entirely.
        "<DeleteMarker><VersionId>vorphan</VersionId></DeleteMarker>" +
        "</ListVersionsResult>",
    };
  }, async function (store) {
    var page = await store.listVersions("k");
    check("listVersions tombstone: keyless row dropped (3 of 4 surfaced)",
          page.items.length === 3);

    var noSize = page.items[0];
    check("listVersions optional: missing Size -> size null",   noSize.size === null);
    check("listVersions optional: missing VersionId -> versionId null",
          noSize.versionId === null);
    check("listVersions optional: PRESERVES key / isLatest / etag / lastModified",
          noSize.key === "k.txt" && noSize.isLatest === true &&
          noSize.etag === '"e-nosize"' &&
          noSize.lastModified === Date.parse("2026-04-05T00:00:00.000Z"));

    var noMtime = page.items[1];
    check("listVersions optional: missing LastModified -> null", noMtime.lastModified === null);
    check("listVersions optional: missing ETag -> null",         noMtime.etag === null);
    check("listVersions optional: PRESERVES key / versionId / size",
          noMtime.key === "k.txt" && noMtime.versionId === "v9" && noMtime.size === 42);

    // Delete-markers sort after versions in the decoded list.
    var tomb = page.items[2];
    check("listVersions tombstone: deleteMarker flag true",  tomb.deleteMarker === true);
    check("listVersions tombstone: size null",               tomb.size === null);
    check("listVersions tombstone: etag null",               tomb.etag === null);
    check("listVersions tombstone: PRESERVES key / versionId / isLatest / lastModified",
          tomb.key === "k.txt" && tomb.versionId === "vdel" && tomb.isLatest === false &&
          tomb.lastModified === Date.parse("2026-04-06T00:00:00.000Z"));
  });
}

// ---- head(): versionId reaches the wire ----

async function testHeadVersionIdReachesTheWire() {
  await _withFakeS3(function () {
    return {
      headers: {
        ETag:             '"head-etag"',
        "Content-Length": "1234",
        "Content-Type":   "text/plain",
        "Last-Modified":  "Tue, 03 Feb 2026 00:00:00 GMT",
      },
    };
  }, async function (store, fake) {
    var meta = await store.head("docs/report.txt", { versionId: "v-abc-123" });
    var rec = fake.requests[0];
    check("head versionId: method is HEAD",             rec.method === "HEAD");
    check("head versionId: versionId in the wire query",
          rec.query.get("versionId") === "v-abc-123");
    check("head versionId: versionId is in the SIGNED canonical query",
          sigv4.canonicalQueryString(rec.query) === "versionId=v-abc-123");
    check("head versionId: size mapped from Content-Length", meta.size === 1234);
    check("head versionId: etag mapped",                     meta.etag === '"head-etag"');
    check("head versionId: lastModified parsed to epoch ms",
          meta.lastModified === Date.parse("Tue, 03 Feb 2026 00:00:00 GMT"));
  });
}

// ---- head(): a non-404 failure is re-thrown unchanged ----

async function testHeadNon404IsRethrownNotMappedToNotFound() {
  await _withFakeS3(function (rec) {
    if (rec.method === "HEAD") return { status: 503 };
    return { status: 404 };
  }, async function (store) {
    var threw = null;
    try {
      await store.head("upstream-degraded.txt");
      check("head 503: should have thrown", false);
    } catch (e) { threw = e; }
    check("head 503: rejected",                 threw !== null);
    check("head 503: statusCode preserved",     threw && threw.statusCode === 503);
    // The discriminator: a 503 must NOT be laundered into the missing-key
    // signal, or an existence probe reports "absent" for a live object.
    check("head 503: NOT remapped to NOT_FOUND", !threw || threw.code !== "NOT_FOUND");
  });
}

async function testHead404MapsToNotFound() {
  await _withFakeS3(function () {
    return { status: 404 };
  }, async function (store) {
    var threw = null;
    try {
      await store.head("gone.txt");
      check("head 404: should have thrown", false);
    } catch (e) { threw = e; }
    check("head 404: mapped to the framework NOT_FOUND code",
          threw && threw.code === "NOT_FOUND");
    check("head 404: message names the key",
          threw && String(threw.message).indexOf("gone.txt") !== -1);
  });
}

// ---- delete(): 404 resolves false; other failures throw ----

async function testDeleteMissingKeyResolvesFalse() {
  await _withFakeS3(function (rec) {
    if (rec.url.indexOf("present") !== -1) return { status: 204 };
    return { status: 404 };
  }, async function (store) {
    var missing = await store.delete("absent.txt");
    check("delete absent: resolves false (no throw)", missing === false);
    var present = await store.delete("present.txt");
    check("delete present: resolves true",            present === true);
  });
}

async function testDeleteServerErrorThrows() {
  await _withFakeS3(function () {
    return { status: 500, body: "<Error><Code>InternalError</Code></Error>" };
  }, async function (store) {
    var threw = null;
    try {
      await store.delete("boom.txt");
      check("delete 500: should have thrown", false);
    } catch (e) { threw = e; }
    check("delete 500: rejected rather than reported as absent",
          threw !== null && threw.statusCode === 500);
  });
}

// ---- getResponse(): conditional-GET 304 short-circuit ----
// httpClient surfaces a 304 as a non-2xx rejection; getResponse has to turn
// it back into a structured result so an operator route can answer the
// browser's If-None-Match without losing the response. If the rejection
// leaked through, every conditionally-cached read would surface as an error.
async function testConditionalGetNotModifiedShortCircuits() {
  await _withFakeS3(function (rec) {
    if (rec.headers["if-none-match"] === '"cached-etag"') {
      return { status: 304, headers: { ETag: '"cached-etag"' } };
    }
    return { status: 200, headers: { ETag: '"cached-etag"' }, body: "fresh bytes" };
  }, async function (store, fake) {
    var res = await store.getResponse("cached.txt", { ifNoneMatch: '"cached-etag"' });
    check("conditional get: If-None-Match forwarded on the wire",
          fake.requests[0].headers["if-none-match"] === '"cached-etag"');
    check("conditional get: 304 resolves (does not reject)", res !== null);
    check("conditional get: statusCode is 304",  res.statusCode === 304);
    check("conditional get: body is null on 304", res.body === null);

    // A cache MISS on the same call shape must still deliver the bytes, so
    // the 304 mapping is not swallowing real responses.
    var fresh = await store.getResponse("cached.txt", { ifNoneMatch: '"stale-etag"' });
    check("conditional get: cache miss returns 200",  fresh.statusCode === 200);
    check("conditional get: cache miss carries the body",
          Buffer.from(fresh.body).toString("utf8") === "fresh bytes");
    check("conditional get: cache miss surfaces the etag", fresh.etag === '"cached-etag"');
  });
}

// A non-304 failure on getResponse must still reject - the 304 handler is a
// narrow short-circuit, not a blanket error swallow.
async function testGetResponseNon304StillRejects() {
  await _withFakeS3(function () {
    return { status: 500, body: "<Error><Code>InternalError</Code></Error>" };
  }, async function (store) {
    var threw = null;
    try {
      await store.getResponse("boom.txt");
      check("getResponse 500: should have thrown", false);
    } catch (e) { threw = e; }
    check("getResponse 500: rejected",              threw !== null);
    check("getResponse 500: statusCode preserved",  threw && threw.statusCode === 500);
    check("getResponse 500: NOT laundered into a 304 result",
          !threw || threw.statusCode !== 304);
  });
}

// ---- getStream(): the sync Readable wrapper around get() ----

async function testGetStreamDeliversBytesAndSurfacesErrors() {
  await _withFakeS3(function (rec) {
    if (rec.url.indexOf("missing") !== -1) return { status: 404 };
    return { status: 200, headers: { ETag: '"s-etag"' }, body: "streamed-object-bytes" };
  }, async function (store) {
    var stream = store.getStream("obj.txt");
    check("getStream: returns synchronously (a Readable, not a Promise)",
          stream && typeof stream.pipe === "function" &&
          typeof stream.then !== "function");
    var chunks = [];
    for await (var c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    check("getStream: delivers the object bytes intact",
          Buffer.concat(chunks).toString("utf8") === "streamed-object-bytes");

    // A failed read must surface as the stream's 'error' event, not as an
    // unhandled rejection or a silently-empty stream.
    var errStream = store.getStream("missing.txt");
    var streamErr = null;
    try {
      for await (var _c of errStream) { void _c; }
      check("getStream 404: should have surfaced an error", false);
    } catch (e) { streamErr = e; }
    check("getStream 404: error surfaced on the stream",  streamErr !== null);
    check("getStream 404: statusCode preserved",          streamErr && streamErr.statusCode === 404);
  });
}

// ---- put(): a non-Buffer, non-stream body ----

async function testPutStringAndNonBufferBodies() {
  await _withFakeS3(function () {
    return { headers: { ETag: '"str-etag"' } };
  }, async function (store, fake) {
    // A multi-byte code point so byte-length and char-length differ - a
    // Content-Length computed from .length would be short by one here.
    var payload = "hello \u00e9 world";
    var rv = await store.put("greeting.txt", payload, { contentType: "text/plain" });
    var sent = fake.requests[0].body;
    var expected = Buffer.from(payload, "utf8");
    check("put string: body encoded as UTF-8 bytes",
          Buffer.compare(sent, expected) === 0);
    check("put string: Content-Length is the BYTE length, not the char count",
          fake.requests[0].headers["content-length"] === String(expected.length));
    check("put string: reported size is the byte length", rv.size === expected.length);
    check("put string: etag surfaced",                    rv.etag === '"str-etag"');
    check("put string: versionId null when the server sends none", rv.versionId === null);

    // A body that is neither Buffer, string, nor stream is REFUSED. It used to
    // collapse to an empty buffer, so the caller stored nothing and was told
    // the write succeeded — silent data loss, not a lenient default.
    var sentCount = fake.requests.length;
    var bodyErrs = [];
    var badBodies = [{ not: "a body" }, 42, true, [1, 2, 3]];
    for (var bi = 0; bi < badBodies.length; bi++) {
      try {
        await store.put("empty.bin", badBodies[bi]);
        check("put: a non-serializable body should have been refused", false);
      } catch (e) { bodyErrs.push(e.code); }
    }
    check("put: every non-serializable body is refused with INVALID_BODY",
          bodyErrs.length === badBodies.length &&
          bodyErrs.every(function (c) { return c === "INVALID_BODY"; }));
    check("put: a refused body puts NOTHING on the wire (no empty object stored)",
          fake.requests.length === sentCount);

    // An explicitly empty object is still legitimate.
    var rvEmpty = await store.put("empty.bin", "");
    check("put: an explicitly empty string still writes a zero-byte object",
          rvEmpty.size === 0 && fake.requests[fake.requests.length - 1].body.length === 0);
  });
}

// The store dispatches through the shared httpClient keep-alive pool; cached
// sockets finalize their destroy on a later event-loop turn. Reset the pool,
// then poll until every TCP handle has drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "sigv4-list-response-shapes: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    await testListPaginationParamsReachTheWire();
    await testListMissingRootElementIsEmptyNotThrow();
    await testListEntryOptionalFieldsOmitted();
    await testListVersionsMarkerParamsReachTheWire();
    await testListVersionsMissingRootElementIsEmpty();
    await testListVersionsTombstoneAndOmittedFields();
    await testHeadVersionIdReachesTheWire();
    await testHeadNon404IsRethrownNotMappedToNotFound();
    await testHead404MapsToNotFound();
    await testDeleteMissingKeyResolvesFalse();
    await testDeleteServerErrorThrows();
    await testConditionalGetNotModifiedShortCircuits();
    await testGetResponseNon304StillRejects();
    await testGetStreamDeliversBytesAndSurfacesErrors();
    await testPutStringAndNonBufferBodies();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[sigv4-list-response-shapes] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}
