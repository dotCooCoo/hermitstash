"use strict";
/**
 * b.atomicFile.conflictPath — last-write-wins conflict-suffix builder.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function testBasicShape() {
  var p = b.atomicFile.conflictPath("/srv/notes.md", {
    timestamp: new Date(Date.UTC(2026, 4, 17, 19, 30, 0, 123)),
  });
  check("inserts .conflict-<stamp>", p === "/srv/notes.conflict-2026-05-17T19-30-00-123Z.md");
}

function testNoExtension() {
  var p = b.atomicFile.conflictPath("/srv/data", {
    timestamp: new Date(Date.UTC(2026, 0, 1)),
  });
  check("no extension preserved", p === "/srv/data.conflict-2026-01-01T00-00-00-000Z");
}

function testCustomTag() {
  var p = b.atomicFile.conflictPath("/srv/notes.md", {
    tag: "merge", timestamp: new Date(Date.UTC(2026, 0, 1)),
  });
  check("custom tag honored",
    p === "/srv/notes.merge-2026-01-01T00-00-00-000Z.md");
}

function testSuffix() {
  var p = b.atomicFile.conflictPath("/srv/notes.md", {
    suffix: "abc123", timestamp: new Date(Date.UTC(2026, 0, 1)),
  });
  check("suffix appended before extension",
    p === "/srv/notes.conflict-2026-01-01T00-00-00-000Z.abc123.md");
}

function testDotfilePreserved() {
  // `.env` has no extension under our rule (leading dot is base).
  var p = b.atomicFile.conflictPath(".env", {
    timestamp: new Date(Date.UTC(2026, 0, 1)),
  });
  check("dotfile treated as no-ext",
    p === ".env.conflict-2026-01-01T00-00-00-000Z");
}

function testWindowsSafe() {
  var p = b.atomicFile.conflictPath("C:\\srv\\notes.md", {
    timestamp: new Date(Date.UTC(2026, 0, 1)),
  });
  check("windows separator honored",
    p === "C:\\srv\\notes.conflict-2026-01-01T00-00-00-000Z.md");
  check("no colons in suffix portion",
    p.split("notes.conflict-")[1].indexOf(":") === -1);
}

function testRefusals() {
  var threw;
  threw = false; try { b.atomicFile.conflictPath(""); } catch (_e) { threw = true; }
  check("empty path throws", threw);
  threw = false; try { b.atomicFile.conflictPath("/x", { tag: "bad space" }); } catch (_e) { threw = true; }
  check("bad tag throws", threw);
  threw = false; try { b.atomicFile.conflictPath("/x", { suffix: "bad/slash" }); } catch (_e) { threw = true; }
  check("bad suffix throws", threw);
}

function run() {
  testBasicShape();
  testNoExtension();
  testCustomTag();
  testSuffix();
  testDotfilePreserved();
  testWindowsSafe();
  testRefusals();
}

if (require.main === module) run();
module.exports = { run: run };
