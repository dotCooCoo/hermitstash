// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.bundler.engine — engine surface tests.
 *
 * Covers passthrough engine (default), engine validation rejection
 * paths, and a synthetic operator-supplied engine that exercises the
 * full transform → write → manifest pipeline including source-map
 * sibling write. The fromEsbuild adapter is asserted by feeding it a
 * stand-in `esbuild` shape that matches the real esbuild's
 * { build({entryPoints, write:false}) → { outputFiles } } contract.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var bundler = require("../../lib/bundler");

function _scratch() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-bundler-engine-"));
  var srcDir = path.join(dir, "src");
  fs.mkdirSync(srcDir);
  var entryPath = path.join(srcDir, "app.js");
  fs.writeFileSync(entryPath, "console.log('hello');\n", "utf8");
  return { dir: dir, entryPath: entryPath, outdir: path.join(dir, "dist"),
           cleanup: function () { fs.rmSync(dir, { recursive: true, force: true }); } };
}

async function testSurface() {
  check("b.bundler.engine present",
        typeof b.bundler.engine === "object");
  check("b.bundler.engine.passthrough is the default-shape engine",
        b.bundler.engine.passthrough && typeof b.bundler.engine.passthrough.transform === "function");
  check("b.bundler.engine.passthrough.name === 'passthrough'",
        b.bundler.engine.passthrough.name === "passthrough");
  check("b.bundler.engine.fromEsbuild is a factory",
        typeof b.bundler.engine.fromEsbuild === "function");
}

async function testPassthroughIsDefault() {
  var s = _scratch();
  try {
    var bld = bundler.create({ entries: { app: s.entryPath }, outdir: s.outdir });
    var rv = await bld.build();
    check("default-engine build produces one output", rv.outputs.length === 1);
    check("output has hash + path",
          typeof rv.outputs[0].hash === "string" && fs.existsSync(rv.outputs[0].path));
    check("output content matches source verbatim",
          fs.readFileSync(rv.outputs[0].path, "utf8") === "console.log('hello');\n");
    check("no sourceMap path on passthrough",
          rv.outputs[0].sourceMapPath === null);
  } finally { s.cleanup(); }
}

async function testEngineValidation() {
  var s = _scratch();
  try {
    function shouldThrow(label, opts, codeRe) {
      var threw = null;
      try { bundler.create(Object.assign({ entries: { app: s.entryPath }, outdir: s.outdir }, opts)); }
      catch (e) { threw = e; }
      check("engine validation: " + label,
            threw && codeRe.test(threw.code || threw.message || ""));
    }
    shouldThrow("rejects non-object engine", { engine: "string" }, /bundler\/bad-engine/);
    shouldThrow("rejects engine missing transform", { engine: { name: "x" } }, /bundler\/bad-engine/);
    shouldThrow("rejects engine missing name",
                { engine: { transform: function () { return {}; } } }, /bundler\/bad-engine/);
    var threwFromEsbuild = null;
    try { bundler.engine.fromEsbuild({}); }
    catch (e) { threwFromEsbuild = e; }
    check("engine validation: fromEsbuild rejects non-esbuild input",
          threwFromEsbuild && /bundler\/bad-engine/.test(threwFromEsbuild.code || ""));
  } finally { s.cleanup(); }
}

async function testCustomEngineTransform() {
  var s = _scratch();
  try {
    var customEngine = {
      name: "uppercase",
      transform: async function (_entryPath, contentBuf) {
        return {
          content: Buffer.from(contentBuf.toString("utf8").toUpperCase(), "utf8"),
          sourceMap: null,
        };
      },
    };
    var bld = bundler.create({
      entries: { app: s.entryPath },
      outdir:  s.outdir,
      engine:  customEngine,
    });
    var rv = await bld.build();
    check("custom-engine output applied transform",
          fs.readFileSync(rv.outputs[0].path, "utf8") === "CONSOLE.LOG('HELLO');\n");
    // Hash reflects the transformed content, not the source.
    check("hash is computed AFTER engine transform",
          rv.outputs[0].hash !== null && rv.outputs[0].path.indexOf(rv.outputs[0].hash) !== -1);
  } finally { s.cleanup(); }
}

async function testEngineSourceMapSibling() {
  var s = _scratch();
  try {
    var customEngine = {
      name: "with-map",
      transform: async function (_entryPath, contentBuf) {
        return {
          content:   contentBuf,
          sourceMap: '{"version":3,"sources":["app.js"],"mappings":"AAAA"}',
        };
      },
    };
    var bld = bundler.create({
      entries: { app: s.entryPath },
      outdir:  s.outdir,
      engine:  customEngine,
    });
    var rv = await bld.build();
    check("output reports sourceMapPath",
          typeof rv.outputs[0].sourceMapPath === "string");
    check("source-map sibling .map file exists on disk",
          fs.existsSync(rv.outputs[0].sourceMapPath));
    check("source-map content matches engine output",
          fs.readFileSync(rv.outputs[0].sourceMapPath, "utf8") ===
          '{"version":3,"sources":["app.js"],"mappings":"AAAA"}');
    check("source-map path is <hashed>.<ext>.map",
          /\.js\.map$/.test(rv.outputs[0].sourceMapPath));
  } finally { s.cleanup(); }
}

async function testFromEsbuildAdapter() {
  var s = _scratch();
  try {
    // Stand-in for the real esbuild module — same { build } shape.
    var fakeEsbuild = {
      build: async function (opts) {
        check("esbuild adapter passes entryPoints",
              Array.isArray(opts.entryPoints) && opts.entryPoints[0] === s.entryPath);
        check("esbuild adapter forces write:false (we own the disk write)",
              opts.write === false);
        check("esbuild adapter passes operator opts through (minify)",
              opts.minify === true);
        // Mimic real esbuild's outputFiles shape.
        return {
          outputFiles: [
            { path: "/.virtual/app.js",
              contents: Buffer.from("console.log(1)\n", "utf8"),
              text:     "console.log(1)\n" },
            { path: "/.virtual/app.js.map",
              contents: Buffer.from('{"version":3}', "utf8"),
              text:     '{"version":3}' },
          ],
        };
      },
    };
    var eng = bundler.engine.fromEsbuild(fakeEsbuild, { minify: true, sourcemap: true });
    check("engine.name === 'esbuild'",   eng.name === "esbuild");
    var bld = bundler.create({
      entries: { app: s.entryPath },
      outdir:  s.outdir,
      engine:  eng,
    });
    var rv = await bld.build();
    check("esbuild-adapter output content == fake esbuild output",
          fs.readFileSync(rv.outputs[0].path, "utf8") === "console.log(1)\n");
    check("esbuild-adapter writes .map sibling",
          fs.existsSync(rv.outputs[0].sourceMapPath));
  } finally { s.cleanup(); }
}

async function testFromEsbuildEmptyOutput() {
  var s = _scratch();
  try {
    var fakeEsbuild = {
      build: async function () { return { outputFiles: [] }; },
    };
    var eng = bundler.engine.fromEsbuild(fakeEsbuild);
    var bld = bundler.create({
      entries: { app: s.entryPath }, outdir: s.outdir, engine: eng,
    });
    var threw = null;
    try { await bld.build(); }
    catch (e) { threw = e; }
    check("empty esbuild output throws bundler/engine-failed",
          threw && /engine-failed|engine-empty/.test(threw.code || threw.message || ""));
  } finally { s.cleanup(); }
}

async function run() {
  await testSurface();
  await testPassthroughIsDefault();
  await testEngineValidation();
  await testCustomEngineTransform();
  await testEngineSourceMapSibling();
  await testFromEsbuildAdapter();
  await testFromEsbuildEmptyOutput();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[bundler-engine] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
