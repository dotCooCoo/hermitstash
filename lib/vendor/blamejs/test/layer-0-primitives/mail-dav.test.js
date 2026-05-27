"use strict";
/**
 * b.mail.dav — CalDAV (RFC 4791) + CardDAV (RFC 6352) HTTP route
 * handlers. Tests surface, dispatch shape, per-principal isolation,
 * iCal / vCard PUT-body validation, REPORT / PROPFIND XML body
 * parsing, ETag precondition handling.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var mailDav = require("../../lib/mail-dav");

// ---- Mock storage ---------------------------------------------------------

function _makeStorage() {
  var cal = Object.create(null);   // principalId -> { calId: { displayName, components: { compId: {bytes, etag, size} } } }
  var ab  = Object.create(null);   // principalId -> { bookId: { displayName, cards: { cardId: {bytes, etag, size} } } }

  function _ensureCal(principalId, calId) {
    if (!cal[principalId]) cal[principalId] = Object.create(null);
    if (calId && !cal[principalId][calId]) {
      cal[principalId][calId] = { displayName: calId, etag: "\"cal-" + calId + "-v1\"", components: Object.create(null) };
    }
    return cal[principalId];
  }
  function _ensureBook(principalId, bookId) {
    if (!ab[principalId]) ab[principalId] = Object.create(null);
    if (bookId && !ab[principalId][bookId]) {
      ab[principalId][bookId] = { displayName: bookId, etag: "\"book-" + bookId + "-v1\"", cards: Object.create(null) };
    }
    return ab[principalId];
  }

  return {
    calendar: {
      listCalendars: async function (principalId) {
        var p = cal[principalId];
        if (!p) return [];
        var out = [];
        var keys = Object.keys(p);
        for (var i = 0; i < keys.length; i++) {
          var c = p[keys[i]];
          out.push({ id: keys[i], displayName: c.displayName, etag: c.etag });
        }
        return out;
      },
      getComponent: async function (principalId, calId, compId) {
        if (!cal[principalId] || !cal[principalId][calId]) return null;
        var c = cal[principalId][calId].components[compId];
        return c ? { id: compId, icalBytes: c.bytes, etag: c.etag, size: c.size } : null;
      },
      listComponents: async function (principalId, calId, filter) {
        void filter;
        if (!cal[principalId] || !cal[principalId][calId]) return [];
        var out = [];
        var keys = Object.keys(cal[principalId][calId].components);
        for (var i = 0; i < keys.length; i++) {
          var c = cal[principalId][calId].components[keys[i]];
          out.push({ id: keys[i], icalBytes: c.bytes, etag: c.etag, size: c.size });
        }
        return out;
      },
      putComponent: async function (principalId, calId, compId, bytes, conds) {
        _ensureCal(principalId, calId);
        var existing = cal[principalId][calId].components[compId];
        if (conds && conds.ifMatch && existing && existing.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        var nextEtag = "\"comp-" + compId + "-" + (existing ? "v2" : "v1") + "\"";
        cal[principalId][calId].components[compId] = {
          bytes: bytes, etag: nextEtag, size: bytes.length,
        };
        return { created: !existing, etag: nextEtag };
      },
      deleteComponent: async function (principalId, calId, compId, conds) {
        if (!cal[principalId] || !cal[principalId][calId]) return { notFound: true };
        var c = cal[principalId][calId].components[compId];
        if (!c) return { notFound: true };
        if (conds && conds.ifMatch && c.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        delete cal[principalId][calId].components[compId];
        return { deleted: true };
      },
      mkcalendar: async function (principalId, calId, props) {
        _ensureCal(principalId, calId);
        if (props && props.displayname) cal[principalId][calId].displayName = props.displayname;
        return { created: true };
      },
    },
    addressbook: {
      listAddressbooks: async function (principalId) {
        var p = ab[principalId];
        if (!p) return [];
        var out = [];
        var keys = Object.keys(p);
        for (var i = 0; i < keys.length; i++) {
          var b = p[keys[i]];
          out.push({ id: keys[i], displayName: b.displayName, etag: b.etag });
        }
        return out;
      },
      getCard: async function (principalId, bookId, cardId) {
        if (!ab[principalId] || !ab[principalId][bookId]) return null;
        var c = ab[principalId][bookId].cards[cardId];
        return c ? { id: cardId, vcardBytes: c.bytes, etag: c.etag, size: c.size } : null;
      },
      listCards: async function (principalId, bookId, filter) {
        void filter;
        if (!ab[principalId] || !ab[principalId][bookId]) return [];
        var out = [];
        var keys = Object.keys(ab[principalId][bookId].cards);
        for (var i = 0; i < keys.length; i++) {
          var c = ab[principalId][bookId].cards[keys[i]];
          out.push({ id: keys[i], vcardBytes: c.bytes, etag: c.etag, size: c.size });
        }
        return out;
      },
      putCard: async function (principalId, bookId, cardId, bytes, conds) {
        _ensureBook(principalId, bookId);
        var existing = ab[principalId][bookId].cards[cardId];
        if (conds && conds.ifMatch && existing && existing.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        var nextEtag = "\"card-" + cardId + "-" + (existing ? "v2" : "v1") + "\"";
        ab[principalId][bookId].cards[cardId] = {
          bytes: bytes, etag: nextEtag, size: bytes.length,
        };
        return { created: !existing, etag: nextEtag };
      },
      deleteCard: async function (principalId, bookId, cardId, conds) {
        if (!ab[principalId] || !ab[principalId][bookId]) return { notFound: true };
        var c = ab[principalId][bookId].cards[cardId];
        if (!c) return { notFound: true };
        if (conds && conds.ifMatch && c.etag !== conds.ifMatch) {
          var e = new Error("etag-mismatch"); e.code = "etag-mismatch"; throw e;
        }
        delete ab[principalId][bookId].cards[cardId];
        return { deleted: true };
      },
      mkcol: async function (principalId, bookId, props) {
        _ensureBook(principalId, bookId);
        if (props && props.displayname) ab[principalId][bookId].displayName = props.displayname;
        return { created: true };
      },
    },
    // Exposed for test pre-population.
    _seedCal:  function (principalId, calId, compId, bytes, etag) {
      _ensureCal(principalId, calId);
      cal[principalId][calId].components[compId] = { bytes: bytes, etag: etag || "\"seed\"", size: bytes.length };
    },
    _seedCard: function (principalId, bookId, cardId, bytes, etag) {
      _ensureBook(principalId, bookId);
      ab[principalId][bookId].cards[cardId] = { bytes: bytes, etag: etag || "\"seed\"", size: bytes.length };
    },
  };
}

function _makeRes() {
  return {
    statusCode: 0,
    headers: Object.create(null),
    body: Buffer.alloc(0),
    setHeader: function (n, v) { this.headers[n.toLowerCase()] = v; },
    end: function (chunk) {
      if (chunk !== undefined) {
        var b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
        this.body = Buffer.concat([this.body, b]);
      }
      this.ended = true;
    },
    ended: false,
  };
}

function _makeReq(method, url, body, headers) {
  return {
    method:  method,
    url:     url,
    headers: headers || {},
    body:    body !== undefined ? body : null,
    user:    null,
    on:      function () {},
    destroy: function () {},
  };
}

function _ical() {
  return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//\r\n" +
         "BEGIN:VEVENT\r\nUID:t1@example.com\r\nDTSTAMP:20260101T120000Z\r\n" +
         "DTSTART:20260101T130000Z\r\nSUMMARY:Test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
}

function _vcard() {
  return "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alice\r\nEMAIL:alice@example.com\r\nEND:VCARD\r\n";
}

// ---- Tests ---------------------------------------------------------------

function testSurface() {
  check("mailDav.create is fn",    typeof mailDav.create === "function");
  check("mailDav.MailDavError is fn", typeof mailDav.MailDavError === "function");

  var dav = mailDav.create({ storage: _makeStorage() });
  check("dav.caldavHandler is fn",    typeof dav.caldavHandler === "function");
  check("dav.carddavHandler is fn",   typeof dav.carddavHandler === "function");
  check("dav.discoveryHandler is fn", typeof dav.discoveryHandler === "function");
  check("dav.dispatchCaldav is fn",   typeof dav.dispatchCaldav === "function");
  check("dav.dispatchCarddav is fn",  typeof dav.dispatchCarddav === "function");
  check("dav.MailDavError is fn",     typeof dav.MailDavError === "function");
}

function testRefusesNoStorage() {
  var threw = false;
  try { mailDav.create({}); }
  catch (e) { threw = !!(e && e.code === "mail-dav/no-storage"); }
  check("refuses no storage opt", threw);
}

function testRefusesNoOpts() {
  var threw = false;
  try { mailDav.create(); }
  catch (e) { threw = !!(e && e.code === "mail-dav/bad-opts"); }
  check("refuses no opts", threw);
}

async function testCaldavOptions() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("OPTIONS", "/alice/"), res);
  check("OPTIONS 200",                  res.statusCode === 200);
  check("OPTIONS DAV header",           /calendar-access/.test(res.headers["dav"]));
  check("OPTIONS Allow has PROPFIND",   /PROPFIND/.test(res.headers["allow"]));
  check("OPTIONS Allow has MKCALENDAR", /MKCALENDAR/.test(res.headers["allow"]));
}

async function testCaldavRefusesNoActor() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav(null, _makeReq("GET", "/alice/cal1/comp1"), res);
  check("no-actor 401", res.statusCode === 401);
}

async function testCaldavRefusesCrossPrincipal() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("GET", "/bob/cal1/comp1"), res);
  check("cross-principal 403", res.statusCode === 403);
}

async function testCaldavRefusesPathTraversal() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("GET", "/alice/cal1/../bob/comp1"), res);
  check("path-traversal 400", res.statusCode === 400);
}

async function testCaldavRefusesPercentEncodedTraversal() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("GET", "/alice/cal1/%2e%2e/bob"), res);
  check("percent-encoded traversal 400", res.statusCode === 400);
}

async function testCaldavPutValidIcal() {
  var storage = _makeStorage();
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCaldav("alice",
    _makeReq("PUT", "/alice/cal1/comp1", Buffer.from(_ical(), "utf8")),
    res);
  check("PUT new comp 201", res.statusCode === 201);
  check("PUT sets ETag",    typeof res.headers["etag"] === "string");
}

async function testCaldavPutRefusesInvalidIcal() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  // RRULE with COUNT > 10000 — calendar-bomb / recursion-DoS defense.
  var bad = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//B//\r\n" +
    "BEGIN:VEVENT\r\nUID:b@x\r\nDTSTAMP:20260101T120000Z\r\nDTSTART:20260101T130000Z\r\n" +
    "RRULE:FREQ=DAILY;COUNT=999999\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
  await dav.dispatchCaldav("alice",
    _makeReq("PUT", "/alice/cal1/bomb", Buffer.from(bad, "utf8")),
    res);
  check("PUT bad iCal → 415", res.statusCode === 415);
}

async function testCaldavPutEtagMismatch() {
  var storage = _makeStorage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"seed-v1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCaldav("alice",
    _makeReq("PUT", "/alice/cal1/comp1",
      Buffer.from(_ical(), "utf8"),
      { "if-match": "\"wrong-etag\"" }),
    res);
  check("PUT ETag mismatch → 412", res.statusCode === 412);
}

async function testCaldavGet() {
  var storage = _makeStorage();
  var bytes = Buffer.from(_ical(), "utf8");
  storage._seedCal("alice", "cal1", "comp1", bytes, "\"e1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("GET", "/alice/cal1/comp1"), res);
  check("GET 200",            res.statusCode === 200);
  check("GET ETag",            res.headers["etag"] === "\"e1\"");
  check("GET body matches",    res.body.toString("utf8") === bytes.toString("utf8"));
  check("GET content-type",    /text\/calendar/.test(res.headers["content-type"]));
}

async function testCaldavGetNotFound() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("GET", "/alice/cal1/missing"), res);
  check("GET 404", res.statusCode === 404);
}

async function testCaldavDelete() {
  var storage = _makeStorage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"e1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCaldav("alice", _makeReq("DELETE", "/alice/cal1/comp1"), res);
  check("DELETE 204", res.statusCode === 204);
}

async function testCaldavPropfindEmptyBody() {
  var storage = _makeStorage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"e1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCaldav("alice",
    _makeReq("PROPFIND", "/alice/cal1/", Buffer.alloc(0),
      { "depth": "1" }),
    res);
  check("PROPFIND 207",        res.statusCode === 207);
  check("PROPFIND multistatus", /multistatus/.test(res.body.toString("utf8")));
  check("PROPFIND response",    /D:response/.test(res.body.toString("utf8")));
}

async function testCaldavPropfindWithPropList() {
  var storage = _makeStorage();
  storage._seedCal("alice", "cal1", "comp1", Buffer.from(_ical(), "utf8"), "\"e1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  var body =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
    "<D:propfind xmlns:D=\"DAV:\">" +
      "<D:prop><D:getetag/><D:displayname/></D:prop>" +
    "</D:propfind>";
  await dav.dispatchCaldav("alice",
    _makeReq("PROPFIND", "/alice/cal1/", Buffer.from(body, "utf8"),
      { "depth": "1" }),
    res);
  check("PROPFIND with prop list 207", res.statusCode === 207);
  check("PROPFIND body has getetag",   /D:getetag/.test(res.body.toString("utf8")));
}

async function testCaldavReportCalendarMultiget() {
  var storage = _makeStorage();
  var bytes = Buffer.from(_ical(), "utf8");
  storage._seedCal("alice", "cal1", "comp1", bytes, "\"e1\"");
  storage._seedCal("alice", "cal1", "comp2", bytes, "\"e2\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  var body =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
    "<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:prop><D:getetag/><C:calendar-data/></D:prop>" +
      "<D:href>/alice/cal1/comp1</D:href>" +
      "<D:href>/alice/cal1/comp2</D:href>" +
    "</C:calendar-multiget>";
  await dav.dispatchCaldav("alice",
    _makeReq("REPORT", "/alice/cal1/", Buffer.from(body, "utf8")),
    res);
  check("REPORT 207",            res.statusCode === 207);
  var bodyStr = res.body.toString("utf8");
  check("REPORT has comp1",      /comp1/.test(bodyStr));
  check("REPORT has comp2",      /comp2/.test(bodyStr));
}

async function testMkcalendar() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  var body =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
    "<C:mkcalendar xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">" +
      "<D:set><D:prop><D:displayname>Personal</D:displayname></D:prop></D:set>" +
    "</C:mkcalendar>";
  await dav.dispatchCaldav("alice",
    _makeReq("MKCALENDAR", "/alice/personal/", Buffer.from(body, "utf8")),
    res);
  check("MKCALENDAR 201", res.statusCode === 201);
}

async function testCarddavSurface() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCarddav("alice", _makeReq("OPTIONS", "/alice/"), res);
  check("CardDAV OPTIONS 200",         res.statusCode === 200);
  check("CardDAV OPTIONS addressbook", /addressbook/.test(res.headers["dav"]));
}

async function testCarddavPutValidVcard() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  await dav.dispatchCarddav("alice",
    _makeReq("PUT", "/alice/book1/card1", Buffer.from(_vcard(), "utf8")),
    res);
  check("CardDAV PUT new 201", res.statusCode === 201);
}

async function testCarddavPutRefusesBadVcard() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  var bad = "BEGIN:VCARD\r\nVERSION:4.0\r\nBOGUSPROP:x\r\nFN:A\r\nEND:VCARD\r\n";
  await dav.dispatchCarddav("alice",
    _makeReq("PUT", "/alice/book1/card1", Buffer.from(bad, "utf8")),
    res);
  check("CardDAV PUT bad vCard → 415", res.statusCode === 415);
}

async function testCarddavGet() {
  var storage = _makeStorage();
  var bytes = Buffer.from(_vcard(), "utf8");
  storage._seedCard("alice", "book1", "card1", bytes, "\"e1\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  await dav.dispatchCarddav("alice", _makeReq("GET", "/alice/book1/card1"), res);
  check("CardDAV GET 200",         res.statusCode === 200);
  check("CardDAV GET content-type", /text\/vcard/.test(res.headers["content-type"]));
  check("CardDAV GET body",         res.body.toString("utf8") === bytes.toString("utf8"));
}

async function testCarddavReportMultiget() {
  var storage = _makeStorage();
  var bytes = Buffer.from(_vcard(), "utf8");
  storage._seedCard("alice", "book1", "card1", bytes, "\"e1\"");
  storage._seedCard("alice", "book1", "card2", bytes, "\"e2\"");
  var dav = mailDav.create({ storage: storage });
  var res = _makeRes();
  var body =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
    "<A:addressbook-multiget xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:carddav\">" +
      "<D:prop><D:getetag/><A:address-data/></D:prop>" +
      "<D:href>/alice/book1/card1</D:href>" +
      "<D:href>/alice/book1/card2</D:href>" +
    "</A:addressbook-multiget>";
  await dav.dispatchCarddav("alice",
    _makeReq("REPORT", "/alice/book1/", Buffer.from(body, "utf8")),
    res);
  check("CardDAV REPORT 207", res.statusCode === 207);
}

function testDiscoveryHandler() {
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  dav.discoveryHandler(_makeReq("GET", "/.well-known/caldav"), res);
  check("discovery 301",          res.statusCode === 301);
  check("discovery Location set", typeof res.headers["location"] === "string");
}

async function testHttpHandlerInvokesDispatch() {
  // Verify the Express-style handler wires through (sync invocation,
  // promise resolves to result).
  var dav = mailDav.create({ storage: _makeStorage() });
  var res = _makeRes();
  var req = _makeReq("OPTIONS", "/alice/");
  req.user = { principalId: "alice" };
  dav.caldavHandler(req, res);
  // Wait one microtask cycle for the dispatch promise.
  await new Promise(function (r) { setImmediate(r); });
  check("caldavHandler routes OPTIONS",
    res.statusCode === 200 && /calendar-access/.test(res.headers["dav"]));
}

async function run() {
  testSurface();
  testRefusesNoStorage();
  testRefusesNoOpts();
  await testCaldavOptions();
  await testCaldavRefusesNoActor();
  await testCaldavRefusesCrossPrincipal();
  await testCaldavRefusesPathTraversal();
  await testCaldavRefusesPercentEncodedTraversal();
  await testCaldavPutValidIcal();
  await testCaldavPutRefusesInvalidIcal();
  await testCaldavPutEtagMismatch();
  await testCaldavGet();
  await testCaldavGetNotFound();
  await testCaldavDelete();
  await testCaldavPropfindEmptyBody();
  await testCaldavPropfindWithPropList();
  await testCaldavReportCalendarMultiget();
  await testMkcalendar();
  await testCarddavSurface();
  await testCarddavPutValidVcard();
  await testCarddavPutRefusesBadVcard();
  await testCarddavGet();
  await testCarddavReportMultiget();
  testDiscoveryHandler();
  await testHttpHandlerInvokesDispatch();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
