// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Wiki env-var surface snapshot — parallel to api-snapshot.json.
 *
 * The wiki app's deploy contract is two-sided:
 *   1. examples/wiki/lib/build-app.js (and route files) reads
 *      `process.env.X` for runtime config.
 *   2. examples/wiki/docker-compose.yml + docker-compose.prod.yml
 *      declares which env vars an operator's deploy needs to set.
 *
 * Both sides must stay aligned. If build-app.js adds a new
 * `process.env.BLAMEJS_FOO` read but docker-compose isn't updated,
 * operators silently get the unset value. If docker-compose lists
 * `BAR: ${BAR:-}` but no source ever reads it, the env knob is
 * dead documentation.
 *
 * NOTE: framework-level env vars (BLAMEJS_LOG_STREAM_*, BLAMEJS_NTP_*,
 * BLAMEJS_DNS_*, etc.) are read INSIDE the framework's lib/ via
 * bootFromEnv() helpers; the wiki app calls those helpers but doesn't
 * directly reference each env var name. The validator unions:
 *   - direct process.env.X reads in the wiki app
 *   - framework env vars read via bootFromEnv calls in lib/
 *     (introspected by walking lib/ for `env.X` patterns)
 * so framework-side env vars surface even though build-app.js doesn't
 * mention them by name.
 *
 * Update the snapshot: BLAMEJS_UPDATE_ENV_SNAPSHOT=1
 *   node examples/wiki/test/validate-env-snapshot.js
 */
var fs = require("node:fs");
var path = require("node:path");

var WIKI_ROOT     = path.resolve(__dirname, "..");
var REPO_ROOT     = path.resolve(__dirname, "..", "..", "..");
var SNAPSHOT_PATH = path.join(WIKI_ROOT, "env-snapshot.json");

// Allowlist — env vars referenced in source that we KNOW shouldn't be
// in docker-compose (Node-builtin or test-only). Each entry needs a
// reason future-self can read.
var SOURCE_ONLY_ALLOWED = {
  "NODE_ENV":  "Node-builtin runtime knob; standard, not a wiki opt",
  "HOSTNAME":  "OS-supplied; used as cloudwatch log-stream discriminator",
  "PORT":      "Standard convention; WIKI_PORT is the canonical wiki opt",
  "LOG_LEVEL": "Standard convention; BLAMEJS_LOG_STREAM_MIN_LEVEL is the framework opt",
  // WIKI_INTEGRATION_* — test-only knobs read by build-app.js when
  // WIKI_INTEGRATION_TEST=1 to wire test backends. Production deploys
  // never set them; they're driven by scripts/test-wiki-integration.js
  // not by docker-compose.
  "WIKI_INTEGRATION_TEST":                    "test-only mount-gate for /test/* routes",
  "WIKI_INTEGRATION_SMTP_HOST":               "test-only — SMTP host for the integration mail transport",
  "WIKI_INTEGRATION_SMTP_PORT":               "test-only — SMTP port for the integration mail transport",
  "WIKI_INTEGRATION_SMTP_EHLO":               "test-only — SMTP EHLO name",
  "WIKI_INTEGRATION_SMTP_REJECT_UNAUTHORIZED": "test-only — STARTTLS verify toggle for the integration transport",
  "WIKI_INTEGRATION_S3_ENDPOINT":             "test-only — S3-compatible endpoint (MinIO) for the integration object-store",
  "WIKI_INTEGRATION_S3_REGION":               "test-only — region for the integration sigv4 backend",
  "WIKI_INTEGRATION_S3_BUCKET":               "test-only — bucket name for the integration object-store",
  "WIKI_INTEGRATION_S3_ACCESS_KEY":           "test-only — access key for the integration sigv4 backend",
  "WIKI_INTEGRATION_S3_SECRET_KEY":           "test-only — secret key for the integration sigv4 backend",
  "WIKI_INTEGRATION_MTLS_DIR":                "test-only — dataDir for the integration mtls-ca instance",
  "BLAMEJS_E2E_DATA_DIR":                     "test-only — wiki e2e data-dir override (Linux container uses /tmp/data-e2e to parallelize with host run)",
  "BLAMEJS_DNS_TRANSPORT":                    "framework runtime opt-out (system|doh|dot) for the default-on DoH; consumed by lib/network-dns.js on first lookup, not at boot",
};

// Env vars in docker-compose that we KNOW shouldn't be read at app
// boot — operator-runtime knobs consumed by the CLI or by primitive
// internals on first use, not on init.
var COMPOSE_ONLY_ALLOWED = {
  "BLAMEJS_AUDIT_PASSPHRASE": "consumed by `blamejs audit ...` CLI runs, not app boot",
  "BLAMEJS_DEPRECATIONS":     "consumed by lib/deprecate.js on first deprecation hit, not boot",
  "BLAMEJS_NTS_REQUIRE":      "passed to b.network.ntp.nts.query() at operator's call site, not boot",
  "BLAMEJS_NTS_SERVERS":      "passed to b.network.ntp.nts.query() at operator's call site, not boot",
  "NODE_ENV":                 "Node-builtin runtime knob; standard, not a wiki opt",
  "LOG_LEVEL":                "Standard convention; BLAMEJS_LOG_STREAM_MIN_LEVEL is the framework opt",
};

// Mask /* ... */ block comments and // line comments with equal-length
// spaces. Preserves string-literal contents (env var names embedded in
// error strings stay visible) and byte offsets. Same shape as the
// harvester at examples/wiki/lib/harvest-env-vars.js.
function _maskComments(src) {
  var out = src.split("");
  var i = 0;
  var n = out.length;
  var inSingle = false, inDouble = false, inTpl = false, inEsc = false;
  while (i < n) {
    var ch = out[i];
    if (inEsc) { inEsc = false; i++; continue; }
    if (inSingle) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "'") inSingle = false;
      i++; continue;
    }
    if (inDouble) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "\"") inDouble = false;
      i++; continue;
    }
    if (inTpl) {
      if (ch === "\\") { inEsc = true; i++; continue; }
      if (ch === "`") inTpl = false;
      i++; continue;
    }
    if (ch === "'") { inSingle = true; i++; continue; }
    if (ch === "\"") { inDouble = true; i++; continue; }
    if (ch === "`") { inTpl = true; i++; continue; }
    if (ch === "/" && i + 1 < n && out[i + 1] === "/") {
      while (i < n && out[i] !== "\n") { out[i] = " "; i++; }
      continue;
    }
    if (ch === "/" && i + 1 < n && out[i + 1] === "*") {
      out[i] = " "; out[i + 1] = " "; i += 2;
      while (i < n) {
        if (out[i] === "*" && i + 1 < n && out[i + 1] === "/") {
          out[i] = " "; out[i + 1] = " "; i += 2; break;
        }
        if (out[i] !== "\n") out[i] = " ";
        i++;
      }
      continue;
    }
    i++;
  }
  return out.join("");
}

function _walk(dir, results, fileFilter) {
  var stat;
  try { stat = fs.statSync(dir); } catch (_e) { return; }
  if (stat.isDirectory()) {
    var skip = ["node_modules", "data", "data-e2e", "public",
                "vendor", "dist", "build", ".git"];
    var entries = fs.readdirSync(dir);
    for (var i = 0; i < entries.length; i++) {
      var name = entries[i];
      if (skip.indexOf(name) !== -1) continue;
      _walk(path.join(dir, name), results, fileFilter);
    }
    return;
  }
  if (!fileFilter(dir)) return;
  // CodeQL js/file-system-race: test/ scaffold scope. This walker reads
  // every framework source file from the worktree the test was invoked
  // against to harvest env-var references for a snapshot diff. There is
  // no attacker model in the snapshot-validator (the worktree is the
  // attestation surface); a swap between fs.statSync and fs.readFileSync
  // would surface as a snapshot mismatch in the diff, not a vuln.
  var src = fs.readFileSync(dir, "utf8");
  // Mask comments (preserve string literals + line offsets) so JSDoc
  // examples like `process.env.X` / `process.env.BLAMEJS_*` don't
  // pollute the env-var catalog.
  src = _maskComments(src);
  // Patterns that count as an env-var read:
  //   process.env.FOO              direct
  //   process.env["FOO"]           bracketed
  //   env.FOO                      framework helper destructure
  //   env["FOO"]                   bracketed
  //   safeEnv.readVar("FOO", ...)  framework's typed-env reader
  var patterns = [
    /process\.env\.([A-Z_][A-Z0-9_]*)/g,
    /process\.env\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\]/g,
    /\benv\.([A-Z_][A-Z0-9_]*)/g,
    /\benv\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\]/g,
    /safeEnv\.readVar\(\s*["']([A-Z_][A-Z0-9_]*)["']/g,
  ];
  for (var p = 0; p < patterns.length; p++) {
    var m;
    while ((m = patterns[p].exec(src)) !== null) {
      var key = m[1];
      if (key) results.add(key);
    }
  }
}

function _isWikiSource(p) {
  return /\.(js|cjs)$/.test(p) && p.indexOf(path.sep + "test" + path.sep) === -1;
}

// Framework env vars we should detect: anything read in lib/ by a
// bootFromEnv() implementation. We walk lib/network*.js, lib/log-stream*.js,
// lib/db.js, etc. — same shape match (env.X / process.env.X).
function _isFrameworkBootSource(p) {
  if (!/\.(js|cjs)$/.test(p)) return false;
  // Limit to known bootFromEnv-using files to keep the noise low.
  var known = [
    "lib/network.js", "lib/network-dns.js", "lib/network-proxy.js",
    "lib/network-tls.js", "lib/network-heartbeat.js",
    "lib/log-stream.js",
    "lib/queue.js",
    "lib/db.js",
  ];
  for (var i = 0; i < known.length; i++) {
    if (p.endsWith(path.normalize(known[i]))) return true;
  }
  return false;
}

function _parseComposeEnvKeys(filePath) {
  var src;
  try { src = fs.readFileSync(filePath, "utf8"); } catch (_e) { return []; }
  // Match `      KEY: ${KEY:-...}` style entries inside the environment:
  // block. Tolerant of indentation; not a full YAML parser, but the
  // shape is operator-documented and stable.
  var keys = [];
  var lines = src.split(/\r?\n/);
  var inEnv = false;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (/^\s+environment:\s*$/.test(line)) { inEnv = true; continue; }
    if (inEnv) {
      // De-indent to service-level closes the environment block.
      if (/^\s{0,4}\S/.test(line) && !/^\s+#/.test(line) &&
          line.indexOf("environment:") === -1) {
        if (/^\s{0,4}[a-z]/.test(line) && line.indexOf(":") !== -1) {
          inEnv = false;
          continue;
        }
      }
      var match = /^\s+([A-Z_][A-Z0-9_]*):\s/.exec(line);
      if (match) keys.push(match[1]);
    }
  }
  return keys;
}

function captureSnapshot() {
  var sourceKeys = new Set();
  ["lib", "routes", "server.js"].forEach(function (rel) {
    _walk(path.join(WIKI_ROOT, rel), sourceKeys, _isWikiSource);
  });
  // Framework env vars consumed by bootFromEnv helpers — surface them so
  // operators see the full set even when build-app.js doesn't name each.
  var frameworkKeys = new Set();
  _walk(path.join(REPO_ROOT, "lib"), frameworkKeys, _isFrameworkBootSource);
  // Combine wiki-source + framework-bootFromEnv reads into one source set.
  frameworkKeys.forEach(function (k) { sourceKeys.add(k); });

  var composeDev  = _parseComposeEnvKeys(path.join(WIKI_ROOT, "docker-compose.yml"));
  var composeProd = _parseComposeEnvKeys(path.join(WIKI_ROOT, "docker-compose.prod.yml"));
  return {
    source:      Array.from(sourceKeys).sort(),
    composeDev:  composeDev.slice().sort(),
    composeProd: composeProd.slice().sort(),
  };
}

function _arrSubtract(a, b) {
  var bSet = new Set(b);
  return a.filter(function (x) { return !bSet.has(x); });
}

function compareSnapshot(captured) {
  var stored;
  try { stored = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8")); }
  catch (_e) { return { initialized: false, drift: [], gaps: [] }; }

  var drift = [];
  ["source", "composeDev", "composeProd"].forEach(function (k) {
    var added   = _arrSubtract(captured[k] || [], stored[k] || []);
    var removed = _arrSubtract(stored[k]   || [], captured[k] || []);
    if (added.length > 0)   drift.push({ field: k, kind: "added",   keys: added });
    if (removed.length > 0) drift.push({ field: k, kind: "removed", keys: removed });
  });

  // Cross-side gap detection: every operator-relevant source key should
  // appear in at least one compose file (unless allowlisted). Every
  // compose key should be readable somewhere.
  var gaps = [];
  var composeUnion = new Set((captured.composeDev || []).concat(captured.composeProd || []));
  (captured.source || []).forEach(function (key) {
    // Skip framework-internal that aren't operator-tunable.
    if (SOURCE_ONLY_ALLOWED[key]) return;
    // Skip wiki-private (WIKI_*) that don't currently need compose docs
    // — they're set inline in dev/prod by the operator.
    if (composeUnion.has(key)) return;
    gaps.push({ side: "source-only", key: key });
  });
  var sourceSet = new Set(captured.source || []);
  composeUnion.forEach(function (key) {
    if (sourceSet.has(key)) return;
    if (COMPOSE_ONLY_ALLOWED[key]) return;
    gaps.push({ side: "compose-only", key: key });
  });
  return { initialized: true, drift: drift, gaps: gaps, stored: stored };
}

function writeSnapshot(captured) {
  fs.writeFileSync(SNAPSHOT_PATH, JSON.stringify(captured, null, 2) + "\n", "utf8");
}

module.exports = {
  captureSnapshot:  captureSnapshot,
  compareSnapshot:  compareSnapshot,
  writeSnapshot:    writeSnapshot,
  SNAPSHOT_PATH:    SNAPSHOT_PATH,
  SOURCE_ONLY_ALLOWED:  SOURCE_ONLY_ALLOWED,
  COMPOSE_ONLY_ALLOWED: COMPOSE_ONLY_ALLOWED,
};

if (require.main === module) {
  var captured = captureSnapshot();
  if (process.env.BLAMEJS_UPDATE_ENV_SNAPSHOT === "1") {
    writeSnapshot(captured);
    console.log("[env-snapshot] wrote " + SNAPSHOT_PATH);
    console.log("  source:      " + captured.source.length);
    console.log("  composeDev:  " + captured.composeDev.length);
    console.log("  composeProd: " + captured.composeProd.length);
    process.exit(0);
  }
  var verdict = compareSnapshot(captured);
  if (!verdict.initialized) {
    console.error("[env-snapshot] snapshot file missing at " + SNAPSHOT_PATH);
    console.error("  Create with: BLAMEJS_UPDATE_ENV_SNAPSHOT=1 node " +
                  path.relative(process.cwd(), __filename));
    process.exit(1);
  }
  var failed = false;
  if (verdict.drift.length > 0) {
    console.error("[env-snapshot] DRIFT — committed snapshot does not match capture:");
    verdict.drift.forEach(function (d) {
      var sign = d.kind === "added" ? "+" : "-";
      console.error("  " + sign + " " + d.field + ": " + d.keys.join(", "));
    });
    failed = true;
  }
  if (verdict.gaps.length > 0) {
    console.error("[env-snapshot] GAPS — env var on one side missing from the other:");
    verdict.gaps.forEach(function (g) {
      if (g.side === "source-only") {
        console.error("  source reads " + g.key + " but neither docker-compose declares it");
        console.error("    -> add to docker-compose.yml + docker-compose.prod.yml under environment:");
      } else {
        console.error("  docker-compose declares " + g.key + " but no source reads it");
        console.error("    -> drop the dead env knob, OR wire process.env." + g.key + " somewhere");
      }
    });
    failed = true;
  }
  if (failed) {
    console.error("[env-snapshot] fix and re-run, OR run with BLAMEJS_UPDATE_ENV_SNAPSHOT=1 to accept.");
    process.exit(1);
  }
  console.log("[env-snapshot] OK — " + captured.source.length + " source keys, " +
              captured.composeDev.length + " composeDev, " +
              captured.composeProd.length + " composeProd");
  process.exit(0);
}
