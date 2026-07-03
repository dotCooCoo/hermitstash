// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// backfill-module-metadata - one-shot script to add @nav / @title /
// @card lines to every @module block in lib/ that's missing them.
//
// Strategy:
//   - Walk lib/ for files with `@module b.X` blocks.
//   - For each module, look up its namespace in NAV_HINTS to get a
//     @nav group; derive a @title from a humanizer + override table;
//     derive a @card description from the first sentence of the
//     existing @intro block.
//   - Edit the source file in-place: insert @nav / @title above the
//     @intro block; append @card last.
//
// Run: node examples/wiki/scripts/backfill-module-metadata.js
// Run with --dry-run to print what would change without writing.

var fs   = require("node:fs");
var path = require("node:path");

var REPO_ROOT = path.join(__dirname, "..", "..", "..");
var LIB_DIR   = path.join(REPO_ROOT, "lib");
var DRY       = process.argv.indexOf("--dry-run") !== -1;

var NAV_HINTS = {
  db: "Data", externalDb: "Data", storage: "Data", objectStore: "Data",
  queue: "Data", cache: "Data", session: "Data", atomicFile: "Data",
  auth: "Identity", permissions: "Identity", apiKey: "Identity",
  breakGlass: "Identity", dualControl: "Identity", subject: "Identity",
  consent: "Identity", credentialHash: "Identity", honeytoken: "Identity",
  authBotChallenge: "Identity",
  crypto: "Crypto", vault: "Crypto", cryptoField: "Crypto",
  pqcGate: "Crypto", pqcAgent: "Crypto", pqcSoftware: "Crypto",
  mtlsCa: "Crypto", tlsExporter: "Crypto", auditSign: "Crypto",
  keychain: "Crypto",
  router: "HTTP", middleware: "HTTP", httpClient: "HTTP",
  websocket: "HTTP", websocketChannels: "HTTP", sse: "HTTP",
  webhook: "Communication", render: "HTTP", staticServe: "HTTP",
  template: "HTTP", errorPage: "HTTP", forms: "HTTP",
  fileUpload: "HTTP", ssrfGuard: "HTTP", requestHelpers: "HTTP",
  cookies: "HTTP", authHeader: "HTTP",
  safeJson: "Validation", safeBuffer: "Validation", safeUrl: "Validation",
  safeSql: "Validation", safeSchema: "Validation", safeRedirect: "Validation",
  safeAsync: "Validation", safeJsonpath: "Validation", safeEnv: "Validation",
  parsers: "Validation", fileType: "Validation",
  csv: "Tools", uuid: "Tools", slug: "Tools", time: "Tools",
  archive: "Tools", pagination: "Tools", i18n: "Tools",
  format: "Tools", config: "Tools", flag: "Tools",
  htmlBalance: "Tools", bundler: "Tools", dev: "Tools",
  mail: "Communication", mailBounce: "Communication",
  notify: "Communication", pubsub: "Communication", cloudEvents: "Communication",
  compliance: "Compliance", retention: "Compliance", legalHold: "Compliance",
  dsr: "Compliance", incident: "Compliance",
  dora: "Compliance", nis2: "Compliance", cra: "Compliance",
  fapi2: "Compliance", fdx: "Compliance", secCyber: "Compliance",
  iabTcf: "Compliance", iabMspa: "Compliance", darkPatterns: "Compliance",
  fda21cfr11: "Compliance", tcpa10dlc: "Compliance",
  auditDailyReview: "Compliance", ddlChangeControl: "Compliance",
  drRunbook: "Compliance",
  audit: "Observability", metrics: "Observability", tracing: "Observability",
  log: "Observability", logStream: "Observability", redact: "Observability",
  otelExport: "Observability", observability: "Observability",
  testing: "Observability", configDrift: "Observability",
  auditChain: "Observability", auditTools: "Observability",
  chainWriter: "Observability",
  cluster: "Production", scheduler: "Production", jobs: "Production",
  backup: "Production", restore: "Production",
  resourceAccessLock: "Production", outbox: "Production", inbox: "Production",
  clusterStorage: "Production", deprecate: "Production",
  ntpCheck: "Production", restoreBundle: "Production",
  budr: "Production", cliHelpers: "Production", appShutdown: "Production",
  retry: "Production", selfUpdate: "Production", tenantQuota: "Production",
  argParser: "Production", circuitBreaker: "Production",
  daemon: "Production", processSpawn: "Production", frameworkSchema: "Production",
  network: "Network", acme: "Network",
  guardCsv: "Guards", guardHtml: "Guards", guardSvg: "Guards",
  guardJson: "Guards", guardYaml: "Guards", guardXml: "Guards",
  guardMarkdown: "Guards", guardEmail: "Guards", guardArchive: "Guards",
  guardImage: "Guards", guardPdf: "Guards", guardJwt: "Guards",
  guardOauth: "Guards", guardGraphql: "Guards", guardShell: "Guards",
  guardRegex: "Guards", guardJsonpath: "Guards", guardTemplate: "Guards",
  guardFilename: "Guards", guardDomain: "Guards", guardUuid: "Guards",
  guardCidr: "Guards", guardTime: "Guards", guardMime: "Guards",
  guardAuth: "Guards", guardAll: "Guards", gateContract: "Guards",
  mcp: "AI", a2a: "AI", graphqlFederation: "AI", aiPref: "AI",
  contentCredentials: "AI",
};

function _humanizeTitle(ns) {
  var spaced = ns.replace(/[A-Z]/g, function (c) { return " " + c; }).replace(/^\s/, "");
  return spaced.replace(/\b\w/g, function (c) { return c.toUpperCase(); });
}

var TITLE_OVERRIDES = {
  csv: "CSV", uuid: "UUID", slug: "Slug",
  i18n: "i18n", html: "HTML", url: "URL", json: "JSON", xml: "XML",
  acme: "ACME", mcp: "Model Context Protocol", a2a: "Agent-to-Agent",
  ai: "AI", iabTcf: "IAB TCF", iabMspa: "IAB MSPA",
  fapi2: "FAPI 2.0", fdx: "FDX", dora: "DORA", gdpr: "GDPR", hipaa: "HIPAA",
  ntpCheck: "NTP Check", apiKey: "API Keys", apiSnapshot: "API Snapshot",
  budr: "BC/DR", drRunbook: "DR Runbook", mtlsCa: "mTLS CA",
  pqcSoftware: "PQC Software", tlsExporter: "TLS Exporter",
  ssrfGuard: "SSRF Guard", cliHelpers: "CLI Helpers", argParser: "Arg Parser",
  authHeader: "Auth Headers", authBotChallenge: "Auth Bot Challenge",
  ddlChangeControl: "DDL Change Control", chainWriter: "Chain Writer",
  auditDailyReview: "Audit Daily Review", auditChain: "Audit Chain Primitives",
  auditTools: "Audit Tools", auditSign: "Audit Signing",
  cryptoField: "Field-Level Crypto", clusterStorage: "Cluster Storage",
  configDrift: "Config Drift", contentCredentials: "Content Credentials",
  darkPatterns: "Dark Patterns", graphqlFederation: "GraphQL Federation",
  htmlBalance: "HTML Balance",
  logStream: "Log Stream", restoreRollback: "Restore Rollback",
  restoreBundle: "Restore Bundle", processSpawn: "Process Spawn",
  frameworkSchema: "Framework Schema", mailBounce: "Mail Bounce",
  cloudEvents: "CloudEvents", appShutdown: "App Shutdown",
  selfUpdate: "Self Update", tenantQuota: "Tenant Quota",
  circuitBreaker: "Circuit Breaker", externalDb: "External Database",
  atomicFile: "Atomic File", breakGlass: "Break Glass",
  credentialHash: "Credential Hash", requestHelpers: "Request Helpers",
  fileUpload: "File Upload", fileType: "File Type",
};

function _firstSentence(intro) {
  if (!intro) return "";
  var s = intro.replace(/\n/g, " ").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "");
  var dot = s.indexOf(". ");
  if (dot !== -1 && dot < 280) return s.slice(0, dot + 1);
  if (s.length > 280) return s.slice(0, 277) + "...";
  return s;
}

function _processFile(file) {
  var src = fs.readFileSync(file, "utf8");
  var blockRe = /\/\*\*([\s\S]*?)\*\//g;
  var m;
  var changed = false;
  var summary = [];
  while ((m = blockRe.exec(src)) !== null) {
    var body = m[1];
    if (!/@module\s+b\./.test(body)) continue;
    var nsMatch = body.match(/@module\s+b\.([a-zA-Z0-9_]+)/);
    if (!nsMatch) continue;
    var ns = nsMatch[1];
    var nav = NAV_HINTS[ns] || "Other";
    var title = TITLE_OVERRIDES[ns] || _humanizeTitle(ns);
    var hasNav   = /\n\s*\*\s*@nav\b/.test(body);
    var hasTitle = /\n\s*\*\s*@title\b/.test(body);
    var hasCard  = /\n\s*\*\s*@card\b/.test(body);
    if (hasNav && hasTitle && hasCard) continue;
    var introMatch = body.match(/\n\s*\*\s*@intro\s*\n([\s\S]*?)(?=\n\s*\*\s*@\w|\*\/|$)/);
    var introBody = introMatch ? introMatch[1].split("\n").map(function (l) {
      return l.replace(/^\s*\*\s?/, "");
    }).join("\n").replace(/^\s+|\s+$/g, "") : "";
    var card = _firstSentence(introBody);
    var moduleLineRe = /(\n)(\s*\*\s*@module\s+b\.[a-zA-Z0-9_]+)([^\n]*)/;
    var insertion = "";
    if (!hasNav)   insertion += "\n * @nav    " + nav;
    if (!hasTitle) insertion += "\n * @title  " + title;
    var newBody = body.replace(moduleLineRe, function (_a, lf, line, rest) {
      return lf + line + rest + insertion;
    });
    if (!hasCard && card) {
      var trimmed = newBody.replace(/\s+$/, "");
      var cardBlock = "\n *\n * @card\n *   " + card;
      newBody = trimmed + cardBlock + "\n ";
    }
    if (newBody !== body) {
      src = src.slice(0, m.index + 3) + newBody + src.slice(m.index + 3 + body.length);
      changed = true;
      summary.push({ ns: ns, file: path.relative(REPO_ROOT, file), addedNav: !hasNav, addedTitle: !hasTitle, addedCard: !hasCard });
      blockRe.lastIndex = m.index + 3 + newBody.length;
    }
  }
  if (changed && !DRY) fs.writeFileSync(file, src);
  return summary;
}

function _walk(dir, out) {
  var entries;
  try { entries = fs.readdirSync(dir); } catch (_e) { return; }
  entries.forEach(function (name) {
    if (name === "vendor" || name === "node_modules") return;
    var full = path.join(dir, name);
    var stat;
    try { stat = fs.statSync(full); } catch (_e) { return; }
    if (stat.isDirectory()) { _walk(full, out); return; }
    if (!/\.js$/.test(name)) return;
    out.push(full);
  });
}

if (require.main === module) {
  var files = [];
  _walk(LIB_DIR, files);
  var totalEdits = 0;
  var perFile = [];
  files.forEach(function (f) {
    var summary = _processFile(f);
    if (summary.length > 0) {
      totalEdits += summary.length;
      perFile.push.apply(perFile, summary);
    }
  });
  console.log("[backfill-module-metadata] " + (DRY ? "DRY-RUN - would update " : "updated ") + totalEdits + " @module blocks");
  perFile.slice(0, 30).forEach(function (s) {
    var added = [];
    if (s.addedNav)   added.push("@nav");
    if (s.addedTitle) added.push("@title");
    if (s.addedCard)  added.push("@card");
    console.log("  " + s.file + " :: b." + s.ns + " - added " + added.join(" + "));
  });
  if (perFile.length > 30) console.log("  ... " + (perFile.length - 30) + " more");
}

module.exports = { NAV_HINTS: NAV_HINTS, TITLE_OVERRIDES: TITLE_OVERRIDES };
