// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// codebase-patterns:allow-file raw-byte-literal — DAV is HTTP-shaped; every
// numeric in this file is an HTTP status code (200 / 201 / 207 / 400 / 401
// / 403 / 404 / 412 / 415 / 500). These are RFC 4791 / RFC 6352 / RFC 2616
// wire-protocol constants, not memory or byte-count caps.
/**
 * @module     b.mail.dav
 * @nav        Mail
 * @title      Mail CalDAV / CardDAV
 * @order      560
 *
 * @intro
 *   CalDAV (RFC 4791) + CardDAV (RFC 6352) HTTP route handlers. Where
 *   the mail-server primitives mount as TCP listeners, the DAV stack
 *   rides the existing HTTP surface: operators mount the returned
 *   handlers under `b.router` / `b.createApp` and reuse their auth
 *   middleware, TLS termination, and rate-limit posture.
 *
 *   The framework owns the wire protocol — method dispatch, XML body
 *   parsing (via `b.xmlC14n.parse`), per-tenant URL isolation,
 *   `If-Match` / `If-None-Match` ETag invariants, response-shape
 *   generation, and (critically) PUT-body validation through
 *   `b.safeIcal.parse` (CalDAV) and `b.safeVcard.parse` (CardDAV).
 *   Operators wire the storage backend — `listCalendars`,
 *   `getComponent`, `listComponents`, `putComponent`,
 *   `deleteComponent` for CalDAV; the equivalent contact-shaped set
 *   for CardDAV — so the framework never assumes a single DB shape.
 *
 *   ## Public surface
 *
 *   ```js
 *   var dav = b.mail.dav.create({
 *     storage: {
 *       calendar: {
 *         listCalendars: async function (principalId) { ... },
 *         getComponent:  async function (principalId, calendarId, componentId) { ... },
 *         listComponents: async function (principalId, calendarId, filter) { ... },
 *         putComponent:  async function (principalId, calendarId, componentId, icalBytes, ifMatch) { ... },
 *         deleteComponent: async function (principalId, calendarId, componentId, ifMatch) { ... },
 *         mkcalendar:    async function (principalId, calendarId, props) { ... },
 *       },
 *       addressbook: {
 *         listAddressbooks: async function (principalId) { ... },
 *         getCard:       async function (principalId, addressbookId, cardId) { ... },
 *         listCards:     async function (principalId, addressbookId, filter) { ... },
 *         putCard:       async function (principalId, addressbookId, cardId, vcardBytes, ifMatch) { ... },
 *         deleteCard:    async function (principalId, addressbookId, cardId, ifMatch) { ... },
 *         mkcol:         async function (principalId, addressbookId, props) { ... },
 *       },
 *     },
 *     profile: "strict",                            // safeIcal / safeVcard
 *     audit:   b.audit,
 *   });
 *
 *   app.use("/.well-known/caldav",  dav.discoveryHandler);
 *   app.use("/.well-known/carddav", dav.discoveryHandler);
 *   app.use("/caldav",  b.middleware.bearerAuth({...}), dav.caldavHandler);
 *   app.use("/carddav", b.middleware.bearerAuth({...}), dav.carddavHandler);
 *   ```
 *
 *   ## URL shape
 *
 *   - CalDAV:   `/caldav/<principal>/<calendar>/<component>.ics`
 *   - CardDAV:  `/carddav/<principal>/<addressbook>/<card>.vcf`
 *
 *   Every URL carries the principal ID at the first path segment.
 *   Cross-principal access is refused at the handler boundary; the
 *   storage backend never sees a principal ID it did not authorize.
 *
 *   ## Verbs (v1)
 *
 *   Common: `OPTIONS`, `PROPFIND`, `REPORT`, `GET`, `PUT`, `DELETE`.
 *   CalDAV-specific: `MKCALENDAR` (RFC 4791 §5.2.1).
 *   CardDAV-specific: `MKCOL` (RFC 4918 §9.3).
 *
 *   PROPFIND responds Multi-Status (207) for `Depth: 0` (resource
 *   props) / `Depth: 1` (collection contents). REPORT bodies
 *   supported: `calendar-query`, `calendar-multiget`,
 *   `addressbook-query`, `addressbook-multiget`. `sync-collection`
 *   (RFC 6578) ships when the storage backend declares its sync-token
 *   capability.
 *
 *   ## Status codes
 *
 *   - 200 — GET / OPTIONS success
 *   - 201 — PUT created / MKCALENDAR / MKCOL success
 *   - 204 — PUT / DELETE success (existing resource)
 *   - 207 — PROPFIND / REPORT Multi-Status (RFC 4918 §13)
 *   - 401 — auth required (operator middleware did not populate actor)
 *   - 403 — cross-principal access / forbidden by storage
 *   - 404 — resource not found
 *   - 412 — `If-Match` ETag mismatch on PUT / DELETE (RFC 4918 §10.4)
 *   - 415 — PUT body failed safeIcal / safeVcard validation
 *
 *   ## Explicitly deferred (v1)
 *
 *   - **WebDAV ACL (RFC 3744)** — operator wires authorization at
 *     their HTTP middleware (per-principal scoping is already
 *     enforced by the URL invariant; richer ACE / privilege grammar
 *     is opt-in).
 *   - **CalDAV scheduling (RFC 6638)** — the iTIP scheduling outbox /
 *     inbox routes call back into `b.mail.submission`; ships in a
 *     later slice so the cross-protocol contract is settled first.
 *   - **Free-busy reports (RFC 4791 §7.10)** — basic free-busy shape
 *     parses; the full availability merge across attendees defers to
 *     the scheduling slice.
 *   - **VTIMEZONE inline composition** — operators reference IANA
 *     timezone names; full VTIMEZONE generation lives in JSCalendar.
 *   - **iMIP (RFC 6047)** — iTIP-over-mail handler defers to the
 *     scheduling slice with its MX hook.
 *
 *   ## CVE defense composition
 *
 *   - `b.safeIcal` rejects RRULE COUNT > 10000 / BYxxx list > 24 →
 *     defends the ical4j RRULE-recursion / recurrence-expansion DoS
 *     class (unbounded RRULE expansion exhausts CPU/memory) on the
 *     PUT path.
 *   - `b.xmlC14n.parse` rejects DOCTYPE / ENTITY in the
 *     PROPFIND / REPORT body → defends XXE / billion-laughs on the
 *     query path.
 *   - URL-encoded path traversal (`..`, `%2e%2e`, null bytes) is
 *     refused before the storage backend sees the IDs.
 *
 * @card
 *   CalDAV (RFC 4791) + CardDAV (RFC 6352) HTTP handlers — operators
 *   mount under their HTTP router. Composes b.safeIcal / b.safeVcard
 *   for PUT-body validation, b.xmlC14n.parse for PROPFIND / REPORT
 *   bodies. Per-principal URL isolation; operator-supplied storage
 *   backend. Defends the RRULE-recursion expansion-DoS class at the PUT boundary.
 */

var C = require("./constants");
var markupEscape = require("./markup-escape").markupEscape;
var safeIcal = require("./safe-ical");
var safeVcard = require("./safe-vcard");
var safeBuffer = require("./safe-buffer");
var validateOpts = require("./validate-opts");
var xmlC14n = require("./xml-c14n");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailDavError = defineClass("MailDavError", { alwaysPermanent: true });

// HTTP method method-set per RFC 4791 §5.3 (CalDAV) + RFC 6352 §6
// (CardDAV) + RFC 4918 §9 (base WebDAV).
var CALDAV_METHODS  = ["OPTIONS", "PROPFIND", "REPORT", "GET", "PUT", "DELETE", "MKCALENDAR"];
var CARDDAV_METHODS = ["OPTIONS", "PROPFIND", "REPORT", "GET", "PUT", "DELETE", "MKCOL"];

// DAV-class header values per RFC 4791 §5.1 + RFC 6352 §6.1.
var CALDAV_DAV_HEADER  = "1, 2, 3, calendar-access";
var CARDDAV_DAV_HEADER = "1, 2, 3, addressbook";

// Per-request body cap — applies to PROPFIND / REPORT bodies AND to
// PUT bodies before they are forwarded to safeIcal / safeVcard. The
// downstream parsers re-cap per profile; this is the outer envelope.
var MAX_REQUEST_BODY_BYTES = C.BYTES.mib(8);

// Per-request actor scope — every operator middleware populates
// `req.user.principalId` (or `req.actor.principalId`); the handler
// refuses on miss.
function _actorPrincipalId(req) {
  var actor = req.user || req.actor || null;
  if (!actor) return null;
  if (typeof actor.principalId === "string") return actor.principalId;
  if (typeof actor.id === "string") return actor.id;
  if (typeof actor.username === "string") return actor.username;
  return null;
}

/**
 * @primitive b.mail.dav.create
 * @signature b.mail.dav.create(opts)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeIcal.parse, b.safeVcard.parse, b.xmlC14n.parse
 *
 * Build a CalDAV + CardDAV route-handler bundle. Returns a handle
 * exposing `caldavHandler` / `carddavHandler` / `discoveryHandler`
 * (Express-style `(req, res, next)` functions) plus `dispatchCaldav` /
 * `dispatchCarddav` for operators on a non-Express transport.
 *
 * @opts
 *   storage:           { calendar, addressbook },     // operator-supplied
 *   profile:           "strict" | "balanced" | "permissive",   // default strict
 *   compliancePosture: "hipaa" | "pci-dss" | "gdpr" | "soc2",  // optional
 *   maxRequestBodyBytes: number,    // default 8 MiB
 *   audit:             b.audit,     // optional
 *
 * @example
 *   var dav = b.mail.dav.create({
 *     storage: {
 *       calendar: { listCalendars, getComponent, listComponents,
 *                   putComponent, deleteComponent, mkcalendar },
 *       addressbook: { listAddressbooks, getCard, listCards,
 *                      putCard, deleteCard, mkcol },
 *     },
 *     profile: "strict",
 *   });
 *
 *   app.use("/.well-known/caldav",  dav.discoveryHandler);
 *   app.use("/.well-known/carddav", dav.discoveryHandler);
 *   app.use("/caldav",  bearerAuth, dav.caldavHandler);
 *   app.use("/carddav", bearerAuth, dav.carddavHandler);
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.dav.create", MailDavError, "mail-dav/bad-opts");
  if (!opts.storage || typeof opts.storage !== "object") {
    throw new MailDavError("mail-dav/no-storage",
      "mail.dav.create: opts.storage is required " +
      "({ calendar: { listCalendars, ... }, addressbook: { listAddressbooks, ... } })");
  }
  var profile = opts.profile || "strict";
  var compliancePosture = opts.compliancePosture || null;
  var maxBody = (typeof opts.maxRequestBodyBytes === "number" &&
                 isFinite(opts.maxRequestBodyBytes) &&
                 opts.maxRequestBodyBytes > 0)
    ? opts.maxRequestBodyBytes
    : MAX_REQUEST_BODY_BYTES;

  var calStorage  = opts.storage.calendar || null;
  var cardStorage = opts.storage.addressbook || null;

  var _emit = auditEmit.emit;

  // ---- URL parsing (per-tenant principal isolation) ----------------------
  //
  // CalDAV URLs:  /caldav/<principal>/<calendar>/<component>
  // CardDAV URLs: /carddav/<principal>/<addressbook>/<card>
  //
  // The mount prefix (`/caldav` / `/carddav`) is stripped by the
  // operator's router before the handler runs. `req.url` therefore
  // starts with `/<principal>/...`.
  function _parsePath(reqUrl) {
    // Strip query string.
    var qIdx = reqUrl.indexOf("?");
    var path = qIdx >= 0 ? reqUrl.slice(0, qIdx) : reqUrl;
    // Refuse path traversal / null bytes before decoding.
    if (path.indexOf("\0") >= 0 ||                                                                       // NUL byte refusal
        /(?:^|\/)\.\.(?:\/|$)/.test(path) ||
        /%2e%2e/i.test(path) ||
        /%00/i.test(path)) {
      return { principalId: null, parts: [], rejected: "traversal" };
    }
    var segs = path.split("/").filter(function (s) { return s.length > 0; });
    var decoded = [];
    for (var i = 0; i < segs.length; i++) {
      try { decoded.push(decodeURIComponent(segs[i])); }
      catch (_e) { return { principalId: null, parts: [], rejected: "malformed-uri" }; }
    }
    return {
      principalId: decoded[0] || null,
      parts:       decoded.slice(1),
      rejected:    null,
    };
  }

  function _refuseStatus(res, code, message) {
    res.statusCode = code;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end(message || "");
  }

  function _readBodyBytes(req) {
    return new Promise(function (resolve, reject) {
      if (req.body !== undefined && req.body !== null) {
        // Body parser already ran.
        if (Buffer.isBuffer(req.body)) {
          if (req.body.length > maxBody) {
            reject(new MailDavError("mail-dav/oversize-body",
              "request body exceeds " + maxBody + " bytes"));
            return;
          }
          resolve(req.body);
          return;
        }
        if (typeof req.body === "string") {
          var buf = Buffer.from(req.body, "utf8");
          if (buf.length > maxBody) {
            reject(new MailDavError("mail-dav/oversize-body",
              "request body exceeds " + maxBody + " bytes"));
            return;
          }
          resolve(buf);
          return;
        }
        // Object — body parser already JSON-parsed; treat as a
        // signal that the operator misconfigured a body parser
        // upstream. Re-serialize as JSON bytes (DAV bodies are XML,
        // so this will fail downstream — fine).
        resolve(Buffer.from(JSON.stringify(req.body), "utf8"));
        return;
      }
      // collectStream's boundedChunkCollector enforces maxBytes inside push()
      // (overflow throws → reject) and destroys the stream on cap/error.
      safeBuffer.collectStream(req, {
        maxBytes:    maxBody,
        errorClass:  MailDavError,
        sizeCode:    "mail-dav/oversize-body",
        sizeMessage: "request body exceeds " + maxBody + " bytes",
      }).then(resolve, reject);
    });
  }

  // ---- Response builders ------------------------------------------------

  function _multiStatus(responses) {
    // RFC 4918 §14.16 — Multi-Status response body.
    var lines = ["<?xml version=\"1.0\" encoding=\"utf-8\"?>"];
    lines.push("<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\" xmlns:A=\"urn:ietf:params:xml:ns:carddav\">");
    for (var i = 0; i < responses.length; i++) {
      var r = responses[i];
      lines.push("<D:response>");
      lines.push("<D:href>" + _xmlEscape(r.href) + "</D:href>");
      if (r.status) {
        lines.push("<D:status>HTTP/1.1 " + r.status + " " + _statusText(r.status) + "</D:status>");
      }
      if (r.propstat) {
        for (var j = 0; j < r.propstat.length; j++) {
          var ps = r.propstat[j];
          lines.push("<D:propstat>");
          lines.push("<D:prop>" + (ps.propXml || "") + "</D:prop>");
          lines.push("<D:status>HTTP/1.1 " + ps.status + " " + _statusText(ps.status) + "</D:status>");
          lines.push("</D:propstat>");
        }
      }
      lines.push("</D:response>");
    }
    lines.push("</D:multistatus>");
    return lines.join("\n");
  }

  function _statusText(code) {
    switch (code) {
      case 200: return "OK";
      case 201: return "Created";
      case 204: return "No Content";
      case 207: return "Multi-Status";
      case 401: return "Unauthorized";
      case 403: return "Forbidden";
      case 404: return "Not Found";
      case 412: return "Precondition Failed";
      case 415: return "Unsupported Media Type";
      case 500: return "Internal Server Error";
      default:  return "Status";
    }
  }

  function _xmlEscape(s) {
    if (s === null || s === undefined) return "";
    return markupEscape(s, { apos: "&apos;" });
  }

  // Render a small subset of well-known DAV / CalDAV / CardDAV
  // properties for PROPFIND responses. Operator-supplied storage
  // resources can carry an `etag` / `ctag` / `displayName` /
  // `resourcetype` field which this picker turns into XML.
  function _renderProps(resource, requestedProps) {
    if (!resource) return "";
    var out = [];
    function maybe(propName, value) {
      if (value === null || value === undefined) return;
      if (requestedProps && requestedProps.length > 0 &&
          requestedProps.indexOf(propName) < 0) return;
      out.push(value);
    }
    maybe("displayname",
      "<D:displayname>" + _xmlEscape(resource.displayName || resource.id || "") + "</D:displayname>");
    maybe("resourcetype",
      "<D:resourcetype>" + (resource.resourcetype || "") + "</D:resourcetype>");
    maybe("getetag",
      resource.etag ? "<D:getetag>" + _xmlEscape(resource.etag) + "</D:getetag>" : null);
    maybe("getcontenttype",
      resource.contentType ? "<D:getcontenttype>" + _xmlEscape(resource.contentType) + "</D:getcontenttype>" : null);
    maybe("getcontentlength",
      typeof resource.size === "number" ?
        "<D:getcontentlength>" + resource.size + "</D:getcontentlength>" : null);
    maybe("getlastmodified",
      resource.lastModified ? "<D:getlastmodified>" + _xmlEscape(resource.lastModified) + "</D:getlastmodified>" : null);
    maybe("calendar-data",
      resource.icalBytes ? "<C:calendar-data>" + _xmlEscape(_bufToText(resource.icalBytes)) + "</C:calendar-data>" : null);
    maybe("address-data",
      resource.vcardBytes ? "<A:address-data>" + _xmlEscape(_bufToText(resource.vcardBytes)) + "</A:address-data>" : null);
    return out.join("");
  }

  function _bufToText(b) {
    if (typeof b === "string") return b;
    if (Buffer.isBuffer(b)) return b.toString("utf8");
    return String(b);
  }

  // ---- PROPFIND body parsing -------------------------------------------
  //
  // Returns `{ allprop: boolean, propname: boolean, props: string[] }`.
  // Empty body == allprop per RFC 4918 §9.1.

  function _parsePropfindBody(bodyBuf) {
    var s = bodyBuf.toString("utf8").trim();
    if (s.length === 0) return { allprop: true, propname: false, props: [] };
    var tree;
    try { tree = xmlC14n.parse(s); }
    catch (e) {
      throw new MailDavError("mail-dav/bad-propfind-body",
        "PROPFIND body XML refused: " + (e && e.message));
    }
    var props = [];
    var allprop = false;
    var propname = false;
    _walkXml(tree, function (node) {
      var local = _localName(node.name);
      if (local === "allprop") allprop = true;
      else if (local === "propname") propname = true;
      else if (local === "prop" && node.children) {
        for (var i = 0; i < node.children.length; i++) {
          var c = node.children[i];
          if (c.type === "element") props.push(_localName(c.name));
        }
      }
    });
    return { allprop: allprop, propname: propname, props: props };
  }

  function _localName(n) {
    if (typeof n !== "string") return "";
    var colonIdx = n.indexOf(":");
    return (colonIdx >= 0 ? n.slice(colonIdx + 1) : n).toLowerCase();
  }

  function _walkXml(node, visitor) {
    if (!node) return;
    if (node.type === "element") visitor(node);
    if (node.children) {
      for (var i = 0; i < node.children.length; i++) {
        _walkXml(node.children[i], visitor);
      }
    }
  }

  // ---- REPORT body parsing ---------------------------------------------
  //
  // Returns `{ kind, props, hrefs, filter }`. Recognized kinds:
  //   calendar-query / calendar-multiget / addressbook-query /
  //   addressbook-multiget.

  function _parseReportBody(bodyBuf) {
    var s = bodyBuf.toString("utf8").trim();
    if (s.length === 0) {
      throw new MailDavError("mail-dav/bad-report-body",
        "REPORT body is empty");
    }
    var tree;
    try { tree = xmlC14n.parse(s); }
    catch (e) {
      throw new MailDavError("mail-dav/bad-report-body",
        "REPORT body XML refused: " + (e && e.message));
    }
    var kind = _localName(tree.name);
    var props = [];
    var hrefs = [];
    var filter = null;
    _walkXml(tree, function (node) {
      var local = _localName(node.name);
      if (local === "prop" && node.children) {
        for (var i = 0; i < node.children.length; i++) {
          var c = node.children[i];
          if (c.type === "element") props.push(_localName(c.name));
        }
      } else if (local === "href" && node.children) {
        for (var j = 0; j < node.children.length; j++) {
          if (node.children[j].type === "text") {
            hrefs.push(node.children[j].value || node.children[j].text || "");
          }
        }
      } else if (local === "filter") {
        filter = node;
      }
    });
    return { kind: kind, props: props, hrefs: hrefs, filter: filter };
  }

  // ---- CalDAV dispatch -------------------------------------------------

  async function dispatchCaldav(actorPrincipalId, req, res) {
    var method = (req.method || "GET").toUpperCase();
    if (CALDAV_METHODS.indexOf(method) < 0) {
      _emit("mail.dav.refused",
        { method: method, kind: "caldav" }, "denied");
      return _refuseStatus(res, 405, "Method not allowed: " + method);
    }
    if (!actorPrincipalId) {
      _emit("mail.dav.refused",
        { method: method, kind: "caldav", reason: "no-actor" }, "denied");
      return _refuseStatus(res, 401, "Authentication required");
    }
    if (!calStorage) {
      return _refuseStatus(res, 501,
        "CalDAV not configured (opts.storage.calendar required)");
    }

    if (method === "OPTIONS") {
      res.statusCode = 200;
      res.setHeader("DAV", CALDAV_DAV_HEADER);
      res.setHeader("Allow", CALDAV_METHODS.join(", "));
      res.setHeader("MS-Author-Via", "DAV");
      res.end();
      _emit("mail.dav.options", { kind: "caldav" });
      return;
    }

    var parsed = _parsePath(req.url || "");
    if (parsed.rejected) {
      _emit("mail.dav.refused",
        { method: method, reason: parsed.rejected }, "denied");
      return _refuseStatus(res, 400, "Bad URL: " + parsed.rejected);
    }
    if (!parsed.principalId) {
      // Allow PROPFIND at the root for principal-discovery patterns.
      if (method !== "PROPFIND") {
        return _refuseStatus(res, 400, "Principal segment required");
      }
    } else if (parsed.principalId !== actorPrincipalId) {
      _emit("mail.dav.refused",
        { method: method, kind: "caldav",
          urlPrincipal: parsed.principalId,
          actorPrincipal: actorPrincipalId,
          reason: "cross-principal" }, "denied");
      return _refuseStatus(res, 403,
        "Cross-principal access refused");
    }

    var calendarId  = parsed.parts[0] || null;
    var componentId = parsed.parts[1] || null;

    try {
      switch (method) {
        case "PROPFIND":   return await _handleCaldavPropfind(req, res, actorPrincipalId, calendarId, componentId);
        case "REPORT":     return await _handleCaldavReport(req, res, actorPrincipalId, calendarId);
        case "GET":        return await _handleCaldavGet(req, res, actorPrincipalId, calendarId, componentId);
        case "PUT":        return await _handleCaldavPut(req, res, actorPrincipalId, calendarId, componentId);
        case "DELETE":     return await _handleCaldavDelete(req, res, actorPrincipalId, calendarId, componentId);
        case "MKCALENDAR": return await _handleMkcalendar(req, res, actorPrincipalId, calendarId);
        default:
          // CALDAV_METHODS allowlist gate is enforced above; this
          // branch is unreachable but eslint requires it.
          return _refuseStatus(res, 405, "Method not allowed: " + method);
      }
    } catch (e) {
      _emit("mail.dav.handler_threw",
        { method: method, kind: "caldav",
          error: (e && e.message) || String(e) }, "failure");
      return _refuseStatus(res, 500, "Server error");
    }
  }

  async function _handleCaldavPropfind(req, res, principalId, calendarId, componentId) {
    var depth = (req.headers && (req.headers.depth || req.headers.Depth)) || "0";
    var bodyBuf = await _readBodyBytes(req);
    var body = _parsePropfindBody(bodyBuf);
    var responses = [];

    if (!calendarId) {
      // Principal-level: list calendars (Depth: 1) or report principal (Depth: 0).
      if (depth === "0") {
        responses.push({
          href: "/caldav/" + principalId + "/",
          propstat: [{
            status: 200,
            propXml: _renderProps({
              displayName: principalId,
              resourcetype: "<D:collection/>",
            }, body.props),
          }],
        });
      } else {
        var cals = await calStorage.listCalendars(principalId);
        responses.push({
          href: "/caldav/" + principalId + "/",
          propstat: [{ status: 200,
            propXml: _renderProps({ displayName: principalId,
              resourcetype: "<D:collection/>" }, body.props) }],
        });
        for (var i = 0; i < (cals || []).length; i++) {
          var cal = cals[i];
          responses.push({
            href: "/caldav/" + principalId + "/" + cal.id + "/",
            propstat: [{ status: 200,
              propXml: _renderProps({
                displayName:  cal.displayName || cal.id,
                resourcetype: "<D:collection/><C:calendar/>",
                etag:         cal.etag,
              }, body.props) }],
          });
        }
      }
    } else if (!componentId) {
      // Calendar collection: list components.
      var components = await calStorage.listComponents(principalId, calendarId, null);
      responses.push({
        href: "/caldav/" + principalId + "/" + calendarId + "/",
        propstat: [{ status: 200,
          propXml: _renderProps({ displayName: calendarId,
            resourcetype: "<D:collection/><C:calendar/>" }, body.props) }],
      });
      if (depth !== "0") {
        for (var j = 0; j < (components || []).length; j++) {
          var c = components[j];
          responses.push({
            href: "/caldav/" + principalId + "/" + calendarId + "/" + c.id,
            propstat: [{ status: 200,
              propXml: _renderProps({
                displayName:  c.id,
                resourcetype: "",
                etag:         c.etag,
                contentType:  "text/calendar; charset=utf-8",
                size:         c.size,
                icalBytes:    body.props.indexOf("calendar-data") >= 0 ? c.icalBytes : null,
              }, body.props) }],
          });
        }
      }
    } else {
      // Single component.
      var comp = await calStorage.getComponent(principalId, calendarId, componentId);
      if (!comp) {
        responses.push({ href: req.url, status: 404 });
      } else {
        responses.push({
          href: req.url,
          propstat: [{ status: 200,
            propXml: _renderProps({
              displayName:  comp.id,
              etag:         comp.etag,
              contentType:  "text/calendar; charset=utf-8",
              size:         comp.size,
              icalBytes:    body.props.indexOf("calendar-data") >= 0 ? comp.icalBytes : null,
            }, body.props) }],
        });
      }
    }
    res.statusCode = 207;
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("DAV", CALDAV_DAV_HEADER);
    res.end(_multiStatus(responses));
    _emit("mail.dav.propfind",
      { kind: "caldav", principalId: principalId, calendarId: calendarId,
        depth: depth, responseCount: responses.length });
  }

  async function _handleCaldavReport(req, res, principalId, calendarId) {
    var bodyBuf = await _readBodyBytes(req);
    var report = _parseReportBody(bodyBuf);
    var responses = [];
    if (report.kind === "calendar-multiget") {
      for (var i = 0; i < report.hrefs.length; i++) {
        var href = report.hrefs[i];
        var hrefParsed = _parsePath(href);
        if (hrefParsed.rejected || hrefParsed.principalId !== principalId) {
          responses.push({ href: href, status: 403 });
          continue;
        }
        var hrefCalId  = hrefParsed.parts[0];
        var hrefCompId = hrefParsed.parts[1];
        var comp = await calStorage.getComponent(principalId, hrefCalId, hrefCompId);
        if (!comp) {
          responses.push({ href: href, status: 404 });
        } else {
          responses.push({
            href: href,
            propstat: [{ status: 200,
              propXml: _renderProps({
                etag:        comp.etag,
                contentType: "text/calendar; charset=utf-8",
                size:        comp.size,
                icalBytes:   comp.icalBytes,
              }, report.props.length > 0 ? report.props : ["getetag", "calendar-data"]) }],
          });
        }
      }
    } else if (report.kind === "calendar-query") {
      var rows = await calStorage.listComponents(principalId, calendarId, report.filter);
      for (var j = 0; j < (rows || []).length; j++) {
        var r = rows[j];
        responses.push({
          href: "/caldav/" + principalId + "/" + calendarId + "/" + r.id,
          propstat: [{ status: 200,
            propXml: _renderProps({
              etag:        r.etag,
              contentType: "text/calendar; charset=utf-8",
              size:        r.size,
              icalBytes:   r.icalBytes,
            }, report.props.length > 0 ? report.props : ["getetag", "calendar-data"]) }],
        });
      }
    } else {
      return _refuseStatus(res, 422, "Unsupported REPORT kind: " + report.kind);
    }
    res.statusCode = 207;
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("DAV", CALDAV_DAV_HEADER);
    res.end(_multiStatus(responses));
    _emit("mail.dav.report",
      { kind: "caldav", reportKind: report.kind, responseCount: responses.length });
  }

  async function _handleCaldavGet(req, res, principalId, calendarId, componentId) {
    if (!componentId) {
      return _refuseStatus(res, 404, "GET requires a component path");
    }
    var comp = await calStorage.getComponent(principalId, calendarId, componentId);
    if (!comp) return _refuseStatus(res, 404, "Component not found");
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/calendar; charset=utf-8");
    if (comp.etag) res.setHeader("ETag", comp.etag);
    res.end(comp.icalBytes);
    _emit("mail.dav.get",
      { kind: "caldav", principalId: principalId, calendarId: calendarId,
        componentId: componentId });
  }

  async function _handleCaldavPut(req, res, principalId, calendarId, componentId) {
    if (!componentId) {
      return _refuseStatus(res, 400, "PUT requires a component path");
    }
    var bodyBuf = await _readBodyBytes(req);
    // Validate iCal body via safeIcal — defends the RRULE-recursion expansion-DoS class at the
    // ingest boundary.
    try {
      safeIcal.parse(bodyBuf, {
        profile: profile,
        compliancePosture: compliancePosture,
      });
    } catch (e) {
      _emit("mail.dav.refused",
        { kind: "caldav", method: "PUT", reason: "ical-refused",
          error: (e && e.code) || (e && e.message) }, "denied");
      return _refuseStatus(res, 415,
        "iCalendar body refused: " + ((e && e.message) || String(e)));
    }
    var ifMatch = (req.headers && (req.headers["if-match"] || req.headers["If-Match"])) || null;
    var ifNoneMatch = (req.headers && (req.headers["if-none-match"] || req.headers["If-None-Match"])) || null;
    var result;
    try {
      result = await calStorage.putComponent(principalId, calendarId, componentId,
        bodyBuf, { ifMatch: ifMatch, ifNoneMatch: ifNoneMatch });
    } catch (e) {
      if (e && (e.code === "etag-mismatch" || e.statusCode === 412)) {
        return _refuseStatus(res, 412, "ETag precondition failed");
      }
      throw e;
    }
    res.statusCode = result && result.created ? 201 : 204;
    if (result && result.etag) res.setHeader("ETag", result.etag);
    res.end();
    _emit("mail.dav.put",
      { kind: "caldav", principalId: principalId, calendarId: calendarId,
        componentId: componentId, created: !!(result && result.created) });
  }

  async function _handleCaldavDelete(req, res, principalId, calendarId, componentId) {
    if (!componentId) {
      return _refuseStatus(res, 400, "DELETE requires a component path");
    }
    var ifMatch = (req.headers && (req.headers["if-match"] || req.headers["If-Match"])) || null;
    try {
      var r = await calStorage.deleteComponent(principalId, calendarId, componentId,
        { ifMatch: ifMatch });
      if (!r || r.notFound) return _refuseStatus(res, 404, "Component not found");
    } catch (e) {
      if (e && (e.code === "etag-mismatch" || e.statusCode === 412)) {
        return _refuseStatus(res, 412, "ETag precondition failed");
      }
      throw e;
    }
    res.statusCode = 204;
    res.end();
    _emit("mail.dav.delete",
      { kind: "caldav", principalId: principalId, calendarId: calendarId,
        componentId: componentId });
  }

  async function _handleMkcalendar(req, res, principalId, calendarId) {
    if (!calendarId) {
      return _refuseStatus(res, 400, "MKCALENDAR requires a calendar path");
    }
    if (typeof calStorage.mkcalendar !== "function") {
      return _refuseStatus(res, 501,
        "MKCALENDAR not supported (storage.calendar.mkcalendar undefined)");
    }
    var bodyBuf = await _readBodyBytes(req);
    var props = Object.create(null);
    if (bodyBuf.length > 0) {
      try {
        var tree = xmlC14n.parse(bodyBuf.toString("utf8"));
        _walkXml(tree, function (node) {
          if (_localName(node.name) === "prop" && node.children) {
            for (var i = 0; i < node.children.length; i++) {
              var c = node.children[i];
              if (c.type === "element" && c.children) {
                var text = "";
                for (var j = 0; j < c.children.length; j++) {
                  if (c.children[j].type === "text") {
                    text += c.children[j].value || c.children[j].text || "";
                  }
                }
                props[_localName(c.name)] = text;
              }
            }
          }
        });
      } catch (_e) {
        return _refuseStatus(res, 400, "MKCALENDAR body XML refused");
      }
    }
    var r = await calStorage.mkcalendar(principalId, calendarId, props);
    res.statusCode = (r && r.created) ? 201 : 200;
    res.end();
    _emit("mail.dav.mkcalendar",
      { principalId: principalId, calendarId: calendarId });
  }

  // ---- CardDAV dispatch ------------------------------------------------

  async function dispatchCarddav(actorPrincipalId, req, res) {
    var method = (req.method || "GET").toUpperCase();
    if (CARDDAV_METHODS.indexOf(method) < 0) {
      _emit("mail.dav.refused",
        { method: method, kind: "carddav" }, "denied");
      return _refuseStatus(res, 405, "Method not allowed: " + method);
    }
    if (!actorPrincipalId) {
      _emit("mail.dav.refused",
        { method: method, kind: "carddav", reason: "no-actor" }, "denied");
      return _refuseStatus(res, 401, "Authentication required");
    }
    if (!cardStorage) {
      return _refuseStatus(res, 501,
        "CardDAV not configured (opts.storage.addressbook required)");
    }

    if (method === "OPTIONS") {
      res.statusCode = 200;
      res.setHeader("DAV", CARDDAV_DAV_HEADER);
      res.setHeader("Allow", CARDDAV_METHODS.join(", "));
      res.setHeader("MS-Author-Via", "DAV");
      res.end();
      _emit("mail.dav.options", { kind: "carddav" });
      return;
    }

    var parsed = _parsePath(req.url || "");
    if (parsed.rejected) {
      _emit("mail.dav.refused",
        { method: method, reason: parsed.rejected }, "denied");
      return _refuseStatus(res, 400, "Bad URL: " + parsed.rejected);
    }
    if (!parsed.principalId) {
      if (method !== "PROPFIND") {
        return _refuseStatus(res, 400, "Principal segment required");
      }
    } else if (parsed.principalId !== actorPrincipalId) {
      _emit("mail.dav.refused",
        { method: method, kind: "carddav",
          urlPrincipal: parsed.principalId,
          actorPrincipal: actorPrincipalId,
          reason: "cross-principal" }, "denied");
      return _refuseStatus(res, 403, "Cross-principal access refused");
    }

    var addressbookId = parsed.parts[0] || null;
    var cardId        = parsed.parts[1] || null;

    try {
      switch (method) {
        case "PROPFIND": return await _handleCarddavPropfind(req, res, actorPrincipalId, addressbookId, cardId);
        case "REPORT":   return await _handleCarddavReport(req, res, actorPrincipalId, addressbookId);
        case "GET":      return await _handleCarddavGet(req, res, actorPrincipalId, addressbookId, cardId);
        case "PUT":      return await _handleCarddavPut(req, res, actorPrincipalId, addressbookId, cardId);
        case "DELETE":   return await _handleCarddavDelete(req, res, actorPrincipalId, addressbookId, cardId);
        case "MKCOL":    return await _handleMkcol(req, res, actorPrincipalId, addressbookId);
        default:
          // CARDDAV_METHODS allowlist gate is enforced above; this
          // branch is unreachable but eslint requires it.
          return _refuseStatus(res, 405, "Method not allowed: " + method);
      }
    } catch (e) {
      _emit("mail.dav.handler_threw",
        { method: method, kind: "carddav",
          error: (e && e.message) || String(e) }, "failure");
      return _refuseStatus(res, 500, "Server error");
    }
  }

  async function _handleCarddavPropfind(req, res, principalId, addressbookId, cardId) {
    var depth = (req.headers && (req.headers.depth || req.headers.Depth)) || "0";
    var bodyBuf = await _readBodyBytes(req);
    var body = _parsePropfindBody(bodyBuf);
    var responses = [];

    if (!addressbookId) {
      if (depth === "0") {
        responses.push({
          href: "/carddav/" + principalId + "/",
          propstat: [{ status: 200,
            propXml: _renderProps({ displayName: principalId,
              resourcetype: "<D:collection/>" }, body.props) }],
        });
      } else {
        var books = await cardStorage.listAddressbooks(principalId);
        responses.push({
          href: "/carddav/" + principalId + "/",
          propstat: [{ status: 200,
            propXml: _renderProps({ displayName: principalId,
              resourcetype: "<D:collection/>" }, body.props) }],
        });
        for (var i = 0; i < (books || []).length; i++) {
          var bk = books[i];
          responses.push({
            href: "/carddav/" + principalId + "/" + bk.id + "/",
            propstat: [{ status: 200,
              propXml: _renderProps({
                displayName:  bk.displayName || bk.id,
                resourcetype: "<D:collection/><A:addressbook/>",
                etag:         bk.etag,
              }, body.props) }],
          });
        }
      }
    } else if (!cardId) {
      var cards = await cardStorage.listCards(principalId, addressbookId, null);
      responses.push({
        href: "/carddav/" + principalId + "/" + addressbookId + "/",
        propstat: [{ status: 200,
          propXml: _renderProps({ displayName: addressbookId,
            resourcetype: "<D:collection/><A:addressbook/>" }, body.props) }],
      });
      if (depth !== "0") {
        for (var j = 0; j < (cards || []).length; j++) {
          var card = cards[j];
          responses.push({
            href: "/carddav/" + principalId + "/" + addressbookId + "/" + card.id,
            propstat: [{ status: 200,
              propXml: _renderProps({
                displayName:  card.id,
                etag:         card.etag,
                contentType:  "text/vcard; charset=utf-8",
                size:         card.size,
                vcardBytes:   body.props.indexOf("address-data") >= 0 ? card.vcardBytes : null,
              }, body.props) }],
          });
        }
      }
    } else {
      var single = await cardStorage.getCard(principalId, addressbookId, cardId);
      if (!single) {
        responses.push({ href: req.url, status: 404 });
      } else {
        responses.push({
          href: req.url,
          propstat: [{ status: 200,
            propXml: _renderProps({
              displayName:  single.id,
              etag:         single.etag,
              contentType:  "text/vcard; charset=utf-8",
              size:         single.size,
              vcardBytes:   body.props.indexOf("address-data") >= 0 ? single.vcardBytes : null,
            }, body.props) }],
        });
      }
    }
    res.statusCode = 207;
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("DAV", CARDDAV_DAV_HEADER);
    res.end(_multiStatus(responses));
    _emit("mail.dav.propfind",
      { kind: "carddav", principalId: principalId,
        addressbookId: addressbookId, depth: depth,
        responseCount: responses.length });
  }

  async function _handleCarddavReport(req, res, principalId, addressbookId) {
    var bodyBuf = await _readBodyBytes(req);
    var report = _parseReportBody(bodyBuf);
    var responses = [];
    if (report.kind === "addressbook-multiget") {
      for (var i = 0; i < report.hrefs.length; i++) {
        var href = report.hrefs[i];
        var hp = _parsePath(href);
        if (hp.rejected || hp.principalId !== principalId) {
          responses.push({ href: href, status: 403 });
          continue;
        }
        var hpBookId = hp.parts[0];
        var hpCardId = hp.parts[1];
        var card = await cardStorage.getCard(principalId, hpBookId, hpCardId);
        if (!card) {
          responses.push({ href: href, status: 404 });
        } else {
          responses.push({
            href: href,
            propstat: [{ status: 200,
              propXml: _renderProps({
                etag:        card.etag,
                contentType: "text/vcard; charset=utf-8",
                size:        card.size,
                vcardBytes:  card.vcardBytes,
              }, report.props.length > 0 ? report.props : ["getetag", "address-data"]) }],
          });
        }
      }
    } else if (report.kind === "addressbook-query") {
      var rows = await cardStorage.listCards(principalId, addressbookId, report.filter);
      for (var j = 0; j < (rows || []).length; j++) {
        var r = rows[j];
        responses.push({
          href: "/carddav/" + principalId + "/" + addressbookId + "/" + r.id,
          propstat: [{ status: 200,
            propXml: _renderProps({
              etag:        r.etag,
              contentType: "text/vcard; charset=utf-8",
              size:        r.size,
              vcardBytes:  r.vcardBytes,
            }, report.props.length > 0 ? report.props : ["getetag", "address-data"]) }],
        });
      }
    } else {
      return _refuseStatus(res, 422, "Unsupported REPORT kind: " + report.kind);
    }
    res.statusCode = 207;
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("DAV", CARDDAV_DAV_HEADER);
    res.end(_multiStatus(responses));
    _emit("mail.dav.report",
      { kind: "carddav", reportKind: report.kind, responseCount: responses.length });
  }

  async function _handleCarddavGet(req, res, principalId, addressbookId, cardId) {
    if (!cardId) return _refuseStatus(res, 404, "GET requires a card path");
    var card = await cardStorage.getCard(principalId, addressbookId, cardId);
    if (!card) return _refuseStatus(res, 404, "Card not found");
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/vcard; charset=utf-8");
    if (card.etag) res.setHeader("ETag", card.etag);
    res.end(card.vcardBytes);
    _emit("mail.dav.get",
      { kind: "carddav", principalId: principalId,
        addressbookId: addressbookId, cardId: cardId });
  }

  async function _handleCarddavPut(req, res, principalId, addressbookId, cardId) {
    if (!cardId) return _refuseStatus(res, 400, "PUT requires a card path");
    var bodyBuf = await _readBodyBytes(req);
    try {
      safeVcard.parse(bodyBuf, {
        profile: profile,
        compliancePosture: compliancePosture,
      });
    } catch (e) {
      _emit("mail.dav.refused",
        { kind: "carddav", method: "PUT", reason: "vcard-refused",
          error: (e && e.code) || (e && e.message) }, "denied");
      return _refuseStatus(res, 415,
        "vCard body refused: " + ((e && e.message) || String(e)));
    }
    var ifMatch = (req.headers && (req.headers["if-match"] || req.headers["If-Match"])) || null;
    var ifNoneMatch = (req.headers && (req.headers["if-none-match"] || req.headers["If-None-Match"])) || null;
    var result;
    try {
      result = await cardStorage.putCard(principalId, addressbookId, cardId,
        bodyBuf, { ifMatch: ifMatch, ifNoneMatch: ifNoneMatch });
    } catch (e) {
      if (e && (e.code === "etag-mismatch" || e.statusCode === 412)) {
        return _refuseStatus(res, 412, "ETag precondition failed");
      }
      throw e;
    }
    res.statusCode = result && result.created ? 201 : 204;
    if (result && result.etag) res.setHeader("ETag", result.etag);
    res.end();
    _emit("mail.dav.put",
      { kind: "carddav", principalId: principalId,
        addressbookId: addressbookId, cardId: cardId,
        created: !!(result && result.created) });
  }

  async function _handleCarddavDelete(req, res, principalId, addressbookId, cardId) {
    if (!cardId) return _refuseStatus(res, 400, "DELETE requires a card path");
    var ifMatch = (req.headers && (req.headers["if-match"] || req.headers["If-Match"])) || null;
    try {
      var r = await cardStorage.deleteCard(principalId, addressbookId, cardId,
        { ifMatch: ifMatch });
      if (!r || r.notFound) return _refuseStatus(res, 404, "Card not found");
    } catch (e) {
      if (e && (e.code === "etag-mismatch" || e.statusCode === 412)) {
        return _refuseStatus(res, 412, "ETag precondition failed");
      }
      throw e;
    }
    res.statusCode = 204;
    res.end();
    _emit("mail.dav.delete",
      { kind: "carddav", principalId: principalId,
        addressbookId: addressbookId, cardId: cardId });
  }

  async function _handleMkcol(req, res, principalId, addressbookId) {
    if (!addressbookId) {
      return _refuseStatus(res, 400, "MKCOL requires an addressbook path");
    }
    if (typeof cardStorage.mkcol !== "function") {
      return _refuseStatus(res, 501,
        "MKCOL not supported (storage.addressbook.mkcol undefined)");
    }
    var bodyBuf = await _readBodyBytes(req);
    var props = Object.create(null);
    if (bodyBuf.length > 0) {
      try {
        var tree = xmlC14n.parse(bodyBuf.toString("utf8"));
        _walkXml(tree, function (node) {
          if (_localName(node.name) === "prop" && node.children) {
            for (var i = 0; i < node.children.length; i++) {
              var c = node.children[i];
              if (c.type === "element" && c.children) {
                var text = "";
                for (var j = 0; j < c.children.length; j++) {
                  if (c.children[j].type === "text") {
                    text += c.children[j].value || c.children[j].text || "";
                  }
                }
                props[_localName(c.name)] = text;
              }
            }
          }
        });
      } catch (_e) {
        return _refuseStatus(res, 400, "MKCOL body XML refused");
      }
    }
    var r = await cardStorage.mkcol(principalId, addressbookId, props);
    res.statusCode = (r && r.created) ? 201 : 200;
    res.end();
    _emit("mail.dav.mkcol",
      { principalId: principalId, addressbookId: addressbookId });
  }

  // ---- HTTP handlers (Express-style) -----------------------------------

  function caldavHandler(req, res) {
    var actorPrincipalId = _actorPrincipalId(req);
    dispatchCaldav(actorPrincipalId, req, res).catch(function (err) {
      _emit("mail.dav.handler_threw",
        { kind: "caldav", error: (err && err.message) || String(err) }, "failure");
      try { _refuseStatus(res, 500, "Server error"); } catch (_e) { /* response already sent */ }
    });
  }

  function carddavHandler(req, res) {
    var actorPrincipalId = _actorPrincipalId(req);
    dispatchCarddav(actorPrincipalId, req, res).catch(function (err) {
      _emit("mail.dav.handler_threw",
        { kind: "carddav", error: (err && err.message) || String(err) }, "failure");
      try { _refuseStatus(res, 500, "Server error"); } catch (_e) { /* response already sent */ }
    });
  }

  // RFC 6764 — .well-known/caldav + .well-known/carddav. SHOULD return
  // a 301 redirect to the principal URL (the operator's auth layer
  // resolves the principal from the bearer token first). For the
  // framework default, redirect to the static collection root and let
  // the client follow current-user-principal.
  function discoveryHandler(req, res) {
    var path = (req.url || "/").toLowerCase();
    var target;
    if (path.indexOf("carddav") >= 0) {
      target = opts.carddavBaseUrl || "/carddav/";
    } else {
      target = opts.caldavBaseUrl || "/caldav/";
    }
    res.statusCode = 301;
    res.setHeader("Location", target);
    res.end();
    _emit("mail.dav.discovery", { target: target });
  }

  return {
    caldavHandler:    caldavHandler,
    carddavHandler:   carddavHandler,
    discoveryHandler: discoveryHandler,
    dispatchCaldav:   dispatchCaldav,
    dispatchCarddav:  dispatchCarddav,
    MailDavError:     MailDavError,
  };
}

module.exports = {
  create:        create,
  MailDavError:  MailDavError,
};
