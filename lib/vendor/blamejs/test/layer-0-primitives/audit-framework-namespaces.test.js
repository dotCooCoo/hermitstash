"use strict";
/**
 * audit FRAMEWORK_NAMESPACES — coverage check across lib/.
 *
 * Every framework primitive that emits an audit event MUST emit on a
 * namespace listed in audit.FRAMEWORK_NAMESPACES. This test walks the
 * lib/ source tree, extracts every action-name string literal passed
 * to safeEmit / _emit / _emitAudit / emitAudit, and asserts that the
 * leading namespace is pre-registered.
 *
 * Without this check a primitive can ship emitting on an unregistered
 * namespace; runtime drops the event with "audit namespace 'X' is not
 * registered" and the operator never knows their telemetry is empty.
 *
 * Run standalone: `node test/layer-0-primitives/audit-framework-namespaces.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs = require("node:fs");
var path = require("node:path");
var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

var LIB_ROOT = path.resolve(__dirname, "..", "..", "lib");

// Match the action-name string literal in any of these emission shapes:
//   _emit("ns.verb", ...)
//   _emitAudit("ns.verb", ...)
//   emitAudit("ns.verb", ...)
//   audit.safeEmit({ action: "ns.verb", ... })
//   audit().safeEmit({ action: "ns.verb", ... })
//   safeEmit({ action: "ns.verb", ... })
// Single-quoted variants too. Action shape:
// `[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+`.
var EMIT_PATTERNS = [
  /(?:_emit|_emitAudit|_auditEmit|emitAudit)\(\s*["']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["']/g,
  /action\s*:\s*["']([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)["']/g,
];

function _allJsFiles(root) {
  var out = [];
  function walk(dir) {
    var entries = fs.readdirSync(dir, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.name === "vendor" || e.name === "node_modules") continue;
      var full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && /\.js$/.test(e.name)) out.push(full);
    }
  }
  walk(root);
  return out;
}

// Strip /* ... */ block comments (covers JSDoc) and // line comments
// from JS source so action-name extraction doesn't pick up tokens
// from operator-facing @example blocks (e.g. `orders.shipped`).
function _stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
}

function _extractEmittedActions(filePath) {
  var src = _stripComments(fs.readFileSync(filePath, "utf8"));
  var found = [];
  for (var p = 0; p < EMIT_PATTERNS.length; p++) {
    var matches = src.matchAll(EMIT_PATTERNS[p]);
    for (var m of matches) {
      found.push({ action: m[1], file: filePath });
    }
  }
  return found;
}

function testEveryEmittedNamespaceIsRegistered() {
  var files = _allJsFiles(LIB_ROOT);
  check("walked at least one lib file",                files.length > 50);

  var allEmitted = [];
  for (var i = 0; i < files.length; i++) {
    var emissions = _extractEmittedActions(files[i]);
    for (var j = 0; j < emissions.length; j++) allEmitted.push(emissions[j]);
  }
  check("scan found at least 30 audit emission sites", allEmitted.length >= 30);

  var registered = new Set(b.audit.FRAMEWORK_NAMESPACES);
  var unregistered = [];
  for (var k = 0; k < allEmitted.length; k++) {
    var ns = allEmitted[k].action.split(".")[0];
    if (!registered.has(ns)) {
      unregistered.push({
        ns:     ns,
        action: allEmitted[k].action,
        file:   path.relative(LIB_ROOT, allEmitted[k].file),
      });
    }
  }

  if (unregistered.length > 0) {
    var summary = unregistered.map(function (u) {
      return u.file + " emits '" + u.action + "' (namespace: '" + u.ns + "')";
    }).join("\n  ");
    console.error("Unregistered audit namespaces emitted by framework primitives:\n  " + summary);
  }
  check("every framework-emitted namespace is in FRAMEWORK_NAMESPACES",
        unregistered.length === 0);
}

function testFrameworkNamespacesShape() {
  var ns = b.audit.FRAMEWORK_NAMESPACES;
  check("FRAMEWORK_NAMESPACES is an array",            Array.isArray(ns));
  check("FRAMEWORK_NAMESPACES has the expected core",  ns.indexOf("auth") !== -1 && ns.indexOf("system") !== -1);
  // Lowercase, underscore-friendly, dot-free per registerNamespace's regex.
  for (var i = 0; i < ns.length; i++) {
    check("FRAMEWORK_NAMESPACES[" + i + "] = " + JSON.stringify(ns[i]) + " matches namespace shape",
          /^[a-z][a-z0-9_]*$/.test(ns[i]));
  }
  // No duplicates.
  var seen = Object.create(null);
  for (var j = 0; j < ns.length; j++) {
    check("FRAMEWORK_NAMESPACES has no duplicate '" + ns[j] + "'", !seen[ns[j]]);
    seen[ns[j]] = true;
  }
}

async function run() {
  testFrameworkNamespacesShape();
  testEveryEmittedNamespaceIsRegistered();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
