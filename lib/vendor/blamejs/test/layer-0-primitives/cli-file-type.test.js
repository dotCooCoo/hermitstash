"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var cli = require("../../lib/cli");

function _captureCtx() {
  var stdout = [];
  var stderr = [];
  return {
    stdout: { write: function (s) { stdout.push(String(s)); } },
    stderr: { write: function (s) { stderr.push(String(s)); } },
    env:    {},
    cwd:    process.cwd(),
    out:    function () { return stdout.join(""); },
    err:    function () { return stderr.join(""); },
  };
}

function _tmpFile(name, bytes) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cli-file-type-"));
  var p = path.join(dir, name);
  fs.writeFileSync(p, bytes);
  return p;
}

async function run() {
  // ---- help ----
  var ctxHelp = _captureCtx();
  var rcHelp = await cli.main(["file-type", "--help"], ctxHelp);
  check("help: exit 0",                     rcHelp === 0);
  check("help: mentions detect subcommand", /detect/.test(ctxHelp.out()));

  // ---- detect: PNG happy path ----
  var pngBytes = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    Buffer.alloc(20),
  ]);
  var pngFile = _tmpFile("test.png", pngBytes);
  var ctxPng = _captureCtx();
  var rcPng = await cli.main(["file-type", "detect", pngFile], ctxPng);
  check("detect PNG: exit 0",                 rcPng === 0);
  check("detect PNG: prints image/png mime",  /mime:\s+image\/png/.test(ctxPng.out()));
  check("detect PNG: prints category image",  /category:\s+image/.test(ctxPng.out()));

  // ---- detect: --json output is valid JSON ----
  var ctxJson = _captureCtx();
  var rcJson = await cli.main(["file-type", "detect", pngFile, "--json"], ctxJson);
  check("detect --json: exit 0",              rcJson === 0);
  var parsed = null;
  try { parsed = JSON.parse(ctxJson.out().trim().split("\n")[0]); }
  catch (_e) { /* leave null */ }
  check("detect --json: valid JSON",          parsed !== null && parsed.mime === "image/png");

  // ---- detect: unknown signature returns exit 1 ----
  var unknownFile = _tmpFile("unknown.txt", Buffer.from("definitely-not-a-known-format-byte-stream"));
  var ctxUnk = _captureCtx();
  var rcUnk = await cli.main(["file-type", "detect", unknownFile], ctxUnk);
  check("detect unknown: exit 1",             rcUnk === 1);
  check("detect unknown: error mentions no signature",
        /no signature matched/.test(ctxUnk.err()));

  // ---- detect: --allowlist match ----
  var ctxAllow = _captureCtx();
  var rcAllow = await cli.main(
    ["file-type", "detect", pngFile, "--allowlist", "image/png,application/pdf"], ctxAllow);
  check("detect --allowlist match: exit 0",   rcAllow === 0);

  // ---- detect: --allowlist mismatch (PNG not in pdf-only allowlist) ----
  var ctxDeny = _captureCtx();
  var rcDeny = await cli.main(
    ["file-type", "detect", pngFile, "--allowlist", "application/pdf"], ctxDeny);
  check("detect --allowlist mismatch: exit 1",  rcDeny === 1);
  check("detect --allowlist mismatch: DISALLOWED_TYPE in error",
        /DISALLOWED_TYPE/.test(ctxDeny.err()));

  // ---- detect: missing file path returns 2 ----
  var ctxMissing = _captureCtx();
  var rcMissing = await cli.main(["file-type", "detect"], ctxMissing);
  check("detect: missing file path → exit 2", rcMissing === 2);

  // ---- unknown subcommand ----
  var ctxBad = _captureCtx();
  var rcBad = await cli.main(["file-type", "scan"], ctxBad);
  check("unknown subcommand → exit 2",       rcBad === 2);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cli-file-type] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
