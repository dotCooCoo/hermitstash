"use strict";
// find-missing-pages — discovers framework namespaces that have no
// wiki page yet, ranks them by primitive count, and emits a task list
// for multi-agent migration.
//
// Inputs:
//   - api-snapshot.json (canonical surface — 198 namespaces under
//     `exports`, each `{ type: "object", members: { ... } }`)
//   - lib/*.js parsed by source-doc-parser (which namespaces already
//     have @module + @primitive blocks)
//   - site.config.js (which namespaces are wired to a page)
//
// Output (when --json or --task-list):
//   wiki-migration-tasks.json — { tasks: [{ namespace, primitiveCount,
//     libFile, suggestedSlug, suggestedGroup, suggestedTitle, ... }] }
//
// Run standalone:
//   node examples/wiki/test/find-missing-pages.js
//   node examples/wiki/test/find-missing-pages.js --task-list
//   node examples/wiki/test/find-missing-pages.js --top=20

var fs   = require("node:fs");
var path = require("node:path");

var parser = require("../lib/source-doc-parser");
var site   = require("../site.config");

var REPO_ROOT  = path.join(__dirname, "..", "..", "..");
var LIB_DIR    = path.join(REPO_ROOT, "lib");
var API_SNAP   = path.join(REPO_ROOT, "api-snapshot.json");
var TASK_OUT   = path.join(REPO_ROOT, "wiki-migration-tasks.json");

var TASK_LIST = process.argv.indexOf("--task-list") !== -1 || process.argv.indexOf("--json") !== -1;
var TOP_ARG   = process.argv.find(function (a) { return a.indexOf("--top=") === 0; });
var TOP       = TOP_ARG ? parseInt(TOP_ARG.split("=")[1], 10) : 50;

// ---- Heuristic: namespace → recommended sidebar group ---------------
// The mapping below is a starter set; agents and operators can
// override per-namespace via site.config.js. Keys are case-sensitive
// b.X identifiers; matching falls through to "Other" when absent.
var GROUP_HINTS = {
  // Data
  db: "Data", externalDb: "Data", storage: "Data", objectStore: "Data",
  queue: "Data", cache: "Data", session: "Data", atomicFile: "Data",
  // Identity
  auth: "Identity", permissions: "Identity", apiKey: "Identity",
  breakGlass: "Identity", dualControl: "Identity", subject: "Identity",
  // Crypto
  crypto: "Crypto", vault: "Crypto", cryptoField: "Crypto",
  pqcGate: "Crypto", pqcAgent: "Crypto", pqcSoftware: "Crypto",
  mtlsCa: "Crypto", tlsExporter: "Crypto", auditSign: "Crypto",
  // HTTP / Web
  router: "HTTP", middleware: "HTTP", httpClient: "HTTP",
  websocket: "HTTP", websocketChannels: "HTTP", sse: "HTTP",
  webhook: "HTTP", render: "HTTP", staticServe: "HTTP", template: "HTTP",
  errorPage: "HTTP", forms: "HTTP", fileUpload: "HTTP",
  ssrfGuard: "HTTP",
  // Validation
  safeJson: "Validation", safeBuffer: "Validation", safeUrl: "Validation",
  safeSql: "Validation", safeSchema: "Validation", safeRedirect: "Validation",
  safeAsync: "Validation", safeJsonpath: "Validation", safeEnv: "Validation",
  parsers: "Validation", fileType: "Validation",
  // Tools
  csv: "Tools", uuid: "Tools", slug: "Tools", time: "Tools",
  archive: "Tools", pagination: "Tools", i18n: "Tools",
  format: "Tools", config: "Tools", flag: "Tools",
  // Communication
  mail: "Communication", mailBounce: "Communication",
  notify: "Communication", pubsub: "Communication", cloudEvents: "Communication",
  // Compliance
  compliance: "Compliance", retention: "Compliance", legalHold: "Compliance",
  dsr: "Compliance", incident: "Compliance",
  dora: "Compliance", nis2: "Compliance", cra: "Compliance",
  fapi2: "Compliance", fdx: "Compliance", secCyber: "Compliance",
  iabTcf: "Compliance", iabMspa: "Compliance", darkPatterns: "Compliance",
  fda21cfr11: "Compliance", tcpa10dlc: "Compliance",
  // Observability
  audit: "Observability", metrics: "Observability", tracing: "Observability",
  log: "Observability", logStream: "Observability", redact: "Observability",
  otelExport: "Observability", observability: "Observability",
  testing: "Observability", configDrift: "Observability",
  // Ops / Production
  cluster: "Production", scheduler: "Production", jobs: "Production",
  backup: "Production", restore: "Production", drRunbook: "Production",
  honeytoken: "Production", resourceAccessLock: "Production",
  outbox: "Production", inbox: "Production",
  // Network
  network: "Network", acme: "Network",
  // Guards
  guardCsv: "Guards", guardHtml: "Guards", guardSvg: "Guards",
  guardJson: "Guards", guardYaml: "Guards", guardXml: "Guards",
  guardMarkdown: "Guards", guardEmail: "Guards", guardArchive: "Guards",
  guardImage: "Guards", guardPdf: "Guards", guardJwt: "Guards",
  guardOauth: "Guards", guardGraphql: "Guards", guardShell: "Guards",
  guardRegex: "Guards", guardJsonpath: "Guards", guardTemplate: "Guards",
  guardFilename: "Guards", guardDomain: "Guards", guardUuid: "Guards",
  guardCidr: "Guards", guardTime: "Guards", guardMime: "Guards",
  guardAuth: "Guards", guardAll: "Guards", gateContract: "Guards",
  // AI / Federation
  mcp: "AI", a2a: "AI", graphqlFederation: "AI", aiPref: "AI",
  contentCredentials: "AI",
};

function _findLibFile(ns) {
  // Convention: framework camelCase namespace → kebab-case file under
  // lib/. Try several patterns: namespace.js, kebab-case.js, and
  // index.js inside a directory.
  var candidates = [
    ns + ".js",
    ns.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }) + ".js",
    path.join(ns, "index.js"),
  ];
  for (var i = 0; i < candidates.length; i++) {
    var p = path.join(LIB_DIR, candidates[i]);
    if (fs.existsSync(p)) return path.relative(REPO_ROOT, p);
  }
  return null;
}

function _annotatedNamespaces(docs) {
  var anns = {};
  Object.keys(docs).forEach(function (file) {
    (docs[file].primitives || []).forEach(function (p) {
      var sig = p.tags && p.tags.primitive;
      if (!sig) return;
      var m = sig.match(/^b\.([a-zA-Z0-9_]+)/);
      if (m) anns[m[1]] = (anns[m[1]] || 0) + 1;
    });
  });
  return anns;
}

function _curatedNamespaces() {
  var c = {};
  site.ENTRIES.forEach(function (e) {
    if (Array.isArray(e.namespaces)) e.namespaces.forEach(function (ns) { c[ns] = e.slug; });
  });
  return c;
}

function _suggestSlug(ns) {
  return ns.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); });
}
function _suggestTitle(ns) {
  return "b." + ns;
}

function find() {
  var snap = JSON.parse(fs.readFileSync(API_SNAP, "utf8"));
  var allNs = Object.keys(snap.exports || {});
  var docs = parser.parseTree(LIB_DIR);
  var annotated = _annotatedNamespaces(docs);
  var curated = _curatedNamespaces();

  var tasks = [];
  allNs.forEach(function (ns) {
    var entry = snap.exports[ns];
    if (!entry) return;
    var primCount = 0;
    var kind = "namespace";
    if (entry.type === "function") {
      // Top-level function (e.g. b.createApp). Treat as a 1-primitive
      // pseudo-namespace. Operators discovering b.X(...) need a wiki
      // page just like any namespaced primitive.
      primCount = 1;
      kind = "function";
    } else if (entry.type === "object" && entry.members) {
      primCount = Object.keys(entry.members).filter(function (k) {
        return entry.members[k].type === "function";
      }).length;
      if (primCount === 0) {
        // Constant-only namespaces (e.g. b.constants) deserve a single
        // page even though no functions are defined. Mark with kind=
        // "constants" so operators can curate manually if desired.
        var constCount = Object.keys(entry.members).length;
        if (constCount > 0) {
          primCount = 0; // 0 indicates "constants only"
          kind = "constants";
        } else {
          return;
        }
      }
    } else {
      return;
    }
    if (annotated[ns] >= Math.max(primCount, 1)) return;
    if (curated[ns]) return;
    var libFile = _findLibFile(ns);
    if (!libFile) return;
    var group = GROUP_HINTS[ns] || "Other";
    tasks.push({
      namespace:        ns,
      kind:             kind,
      primitiveCount:   primCount,
      annotated:        annotated[ns] || 0,
      libFile:          libFile,
      suggestedSlug:    _suggestSlug(ns),
      suggestedTitle:   _suggestTitle(ns),
      suggestedGroup:   group,
    });
  });

  // Sort: largest unannotated namespaces first (highest leverage).
  tasks.sort(function (a, b) {
    return (b.primitiveCount - b.annotated) - (a.primitiveCount - a.annotated);
  });

  return tasks;
}

function _emitTaskList(tasks) {
  var doc = {
    generatedAt:   new Date().toISOString(),
    totalMissing:  tasks.length,
    totalPending:  tasks.reduce(function (n, t) { return n + (t.primitiveCount - t.annotated); }, 0),
    tasks:         tasks,
  };
  fs.writeFileSync(TASK_OUT, JSON.stringify(doc, null, 2));
  console.log("[find-missing-pages] wrote " + tasks.length + " task(s) to " + path.relative(process.cwd(), TASK_OUT));
  console.log("[find-missing-pages] " + doc.totalPending + " primitives pending across " + tasks.length + " namespaces");
}

function _emitReport(tasks) {
  if (tasks.length === 0) {
    console.log("[find-missing-pages] OK — every function-bearing namespace is documented");
    return;
  }
  console.log("[find-missing-pages] " + tasks.length + " namespace(s) without wiki pages:");
  console.log("");
  console.log("  " + "namespace".padEnd(22) + "primitives  group           libFile");
  console.log("  " + "---------".padEnd(22) + "----------  ---------       -------");
  tasks.slice(0, TOP).forEach(function (t) {
    var pendStr = (t.primitiveCount - t.annotated) + "/" + t.primitiveCount;
    console.log("  " +
      t.namespace.padEnd(22) +
      pendStr.padEnd(12) +
      t.suggestedGroup.padEnd(16) +
      t.libFile);
  });
  if (tasks.length > TOP) {
    console.log("");
    console.log("  ... " + (tasks.length - TOP) + " more (run with --top=N to see).");
  }
  console.log("");
  console.log("  Run with --task-list to write the full machine-readable plan.");
}

if (require.main === module) {
  var tasks = find();
  if (TASK_LIST) _emitTaskList(tasks);
  else           _emitReport(tasks);
}

module.exports = { find: find };
