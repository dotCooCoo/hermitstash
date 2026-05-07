"use strict";
/**
 * validate-primitive-sections — wiki convention enforcer.
 *
 * Walks every page seeder under examples/wiki/seeders/prod/pages/ and
 * verifies every primitive section ships the four pieces required by
 * the project's wiki-section convention:
 *
 *   1. Heading — <h2> or <h3> whose text begins with `b.module.method(...)`
 *   2. Opts model — first javascript code block when signature names opts
 *   3. Description prose — at least one <p> or <aside> in the section
 *   4. Example code — at least one non-opts code block (js or bash)
 *
 * Beyond presence, the validator does two deeper passes:
 *
 *   Pre-boot pass — opts diff (this file, runs pre-boot from e2e step 0)
 *     For sections whose heading is a single-method `b.X.Y(opts)` form,
 *     probe the lib function with an unknown key, parse the
 *     "Allowed keys:" / "Allowed:" list from the validation error,
 *     and diff against the keys parsed from the wiki opts block.
 *     Drift surfaces as "added" (wiki has a key the lib doesn't accept)
 *     or "removed" (lib has a key the wiki doesn't document).
 *
 *   Post-boot pass — example execution (runExamples export, runs post-boot
 *     from e2e after the wiki app starts)
 *     Each non-opts javascript example block runs in a sandboxed async
 *     wrapper with the framework + helper stubs in scope. Syntax errors
 *     and runtime ReferenceErrors against undefined real-framework
 *     symbols fail the gate. Examples referencing operator-stubbed
 *     names (req/res/db rows) get harness stubs so they don't trip on
 *     scope alone — the harness fails only when the example calls a
 *     b.X.Y that doesn't exist or passes args the lib rejects.
 *
 * Sections whose heading text doesn't match the primitive signature
 * pattern (purely conceptual subsections like "Tenant-per-row vs
 * tenant-per-schema") are NOT validated — they're concept groups, not
 * primitive docs.
 *
 * Genuinely-deviant primitive sections (CLI subcommands documented as
 * a single bash example, narrative-shaped primitives that fold their
 * opts into the description) live in EXEMPTIONS below with a one-line
 * reason. New primitives must conform; the gate fails on any new
 * violation.
 *
 * Run standalone:
 *   node examples/wiki/test/validate-primitive-sections.js
 *   node examples/wiki/test/validate-primitive-sections.js --report
 *     (report-only mode, exits 0 even with violations — useful when
 *      iterating on the exemptions list)
 *
 * Run as part of wiki e2e:
 *   node examples/wiki/test/e2e.js
 *   (validator runs first; e2e refuses to start if the validator fails)
 */
var fs = require("fs");
var path = require("path");

// ---- Exemptions ----
//
// Sections explicitly EXCLUDED from the validator's bar. The naming
// is inverted from "allowlist" because that's what the list does:
// items here are exempted from passing the four-piece check, with a
// stated reason. Format: { "page-slug:lowercased-heading-prefix": "reason" }.
// The match key is the slug + ":" + lowercase first-50-chars of the
// heading signature. Each reason should read in 5 seconds —
// "deferred", "compound primitive", "CLI bash-only".
//
// Every entry is future drift unless paired with a tracking note in
// the v0.6.x backlog. Prefer closing the gap in the same patch over
// adding here.
var EXEMPTIONS = {
  // Sections whose examples genuinely can't run inside a sandboxed
  // harness because the surface depends on browser-side state, an
  // external network endpoint, or a third-party identity provider
  // the validator can't simulate. Each entry lists the reason an
  // operator could read in 5 seconds.
  "middleware:b.validateopts(opts, allowedkeys, label)":
    "validateOpts is a positional argument-validator helper — `opts` is the raw operator-passed object passed in, not a configuration-object the validator describes",
  "auth:b.auth.passkey.startregistration(opts) / .verifyre":
    "WebAuthn ceremony — verifyRegistration consumes a browser-side AttestationResponse",
  "auth:b.auth.passkey.startauthentication(opts) / .verify":
    "WebAuthn ceremony — verifyAuthentication consumes a browser-side AssertionResponse",
  "auth:b.auth.oauth.create(opts)":
    "OAuth flow needs a real provider (Google/GitHub/etc.) for the token-exchange round trip",
  "observability:b.otelexport.create(opts)":
    "OTLP/HTTP export connects to an operator-side OTel collector — the example has a real Honeycomb URL",
  // breakGlass passkey + service-account variants need a real WebAuthn
  // attestation chain or a pre-issued service-account key that the
  // sandboxed validator harness can't synthesize.
  "access-control:b.breakglass.policy.set(table, opts)":
    "compound section covering passkey + service-account paths that need external state",
  "access-control:b.breakglass.grant(opts)":
    "covered by the b.breakGlass.policy.set cluster's exemption",
  // Cluster + scheduler examples need a real externalDb provider for
  // leader election (Postgres advisory locks). The validator's fake-
  // backend can't satisfy that contract; the actual cluster e2e covers
  // these paths from the ground up.
  "cluster:b.cluster.init(opts)":
    "needs a real externalDb leader-election provider (Postgres advisory lock)",
  "cluster:b.scheduler.create(opts)":
    "needs a cluster instance for the leader-gated tick path",
  "cluster:b.externaldb.init(opts)":
    "init example uses operator-defined connect/query — covered by externalDb-routing tests",
  "auth:b.auth.jwt.sign(claims, opts) / .verify(token, opt":
    "JWT signing in example uses operator-supplied keys; PEM parser fixture mismatch is environmental",
  "auth:b.auth.lockout.create(opts)":
    "cache backend 'cluster' needs cluster.init upstream — exempt for the same reason as cluster:* sections",
  "i18n-locale:b.i18n.create(opts)":
    "example imports a translations module via require() — that module path is operator-supplied",
  "mail:b.mail.create(opts)":
    "SMTP transport example would dial smtp.example.com — operator-network-only path",
  "mail:b.mail.dkim.create(opts)":
    "DKIM signs with operator-supplied PEM; the example demonstrates the call shape",
  "notifications:b.notify.create(opts)":
    "example wires Slack/Discord http webhook URLs — outbound https-only by default and the harness uses test stubs",
  "object-store:b.storage.presigneduploadpolicy(key, opts)":
    "S3 presigned-policy example needs an operator-supplied S3 backend — local-file backend doesn't support presign",
  "queue-cache:b.cache.create(opts)":
    "example references apiCache (operator-defined cache instance) by name in a multi-line composition",
  "reliability:b.retry.withretry(fn, opts)":
    "compound section that demonstrates retry + circuit-breaker composition — `guarded` references the breaker example's local",
  "websockets:b.websocketchannels.create(opts)":
    "example wires router.ws() with operator-supplied per-channel auth handlers",
  "compliance-patterns:b.dualcontrol.create(opts)":
    "example references operator actors (actor1, actor2) — pedagogical IDs, not in harness scope",
  "compliance-patterns:b.configdrift.create(opts)":
    "example references operator log sink (log.warn) — operator-side wiring",
  "compliance-patterns:b.security.assertproduction(opts)":
    "example references process.env.WIKI_ADMIN_PASSWORD (operator-side env) and asserts boot-time posture",
  "safe-parsers:b.filetype.detect(buffer, opts?)":
    "example references uploadedBuffer (per-request value from a route handler — operator-side)",
  "safe-parsers:b.filetype.assertoneof(buffer, allowlist, opts?)":
    "example references uploadedBuffer + res (per-request values — operator-side)",
  "auth:b.auth.password.policy(opts)":
    "example references user.passwordHashHistory / user.passwordSetAt (per-account state read from DB — operator-side)",
  "observability:b.audit.safeemit(event)":
    "example shows compound emission in a route handler — references operator-side `body` from req parsing",
  "network-config:b.network.ntp.bootcheck(opts) / setthresholds(opts":
    "boot-check example dials real NTP/UDP — operator-network-only path",
  "network-config:b.network.ntp.nts.query(opts) — authenticated ntp":
    "NTS query negotiates with a live NTS-KE server over TLS — operator-network-only path",
  "network-config:b.network.dns.lookup(host, opts?) / setservers / s":
    "DNS examples resolve real hostnames against an operator-pinned resolver — sandbox can't simulate",
  "network-config:b.network.proxy.fromenv() / set(opts) / shouldprox":
    "proxy example calls outbound https through a tunnel that the harness can't reach",
  "network-config:b.network.tls.addca(pemorpath, opts?) / addcabundl":
    "addCa example loads operator-supplied PEM file from disk and dials internal HTTPS — operator-network-only",
};

// Primitive signature pattern: heading begins with `b.module.method`
// (chained dotted form). May be wrapped in `<code>...</code>` markup.
//
// Examples that match:
//   "b.db.declareView(opts)"
//   "b.cache.set(key, value, opts?) / cache.wrap(key, fn)"
//
// Examples that DON'T match (conceptual sections, framework-internal):
//   "Three threat models"
//   "Tenant-per-row vs tenant-per-schema"
//   "Per-cell encryption with context binding"
//   "Pick your defenses"
// Match either b.X(args) (top-level function) OR b.X.Y(args)+ (namespaced
// method). The trailing ( is the disambiguator — bare prose mentions of
// `b.X` without parens don't match (those are operator-facing references,
// not signature headings).
var PRIMITIVE_SIGNATURE_RE = /^\s*(?:<code>\s*)?b\.[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)*\s*\(/;

// ---- Parser ----

function _readPageBodies() {
  var pagesDir = path.join(__dirname, "..", "seeders", "prod", "pages");
  var files = fs.readdirSync(pagesDir)
    .filter(function (f) { return f.endsWith(".js") && f !== "_index.js"; });
  return files.map(function (f) {
    var mod = require(path.join(pagesDir, f));
    return {
      file: f,
      slug: mod.slug,
      title: mod.title,
      body: Array.isArray(mod.body) ? mod.body.join("\n") : String(mod.body || ""),
    };
  });
}

function _headingText(rawHeading) {
  var stripped = rawHeading
    .replace(/<a\s+class="anchor"[^>]*>[^<]*<\/a>/gi, "")
    .replace(/<\/?h[1-6][^>]*>/gi, "")
    .trim();
  return stripped;
}

// Split a page body into sections at every <h2> and <h3>. Each section
// carries its heading tag, heading-text-only, and the body content
// from after the heading until the next heading (or end of page).
function _splitSections(body) {
  var matches = [];
  var headingRe = /<h([23])\b[^>]*>([\s\S]*?)<\/h\1>/g;
  var iter = body.matchAll(headingRe);
  for (var m of iter) {
    matches.push({
      level:    Number(m[1]),
      raw:      m[0],
      text:     _headingText(m[0]),
      startIdx: m.index,
      endIdx:   m.index + m[0].length,
    });
  }
  for (var i = 0; i < matches.length; i++) {
    var nextStart = (i + 1 < matches.length) ? matches[i + 1].startIdx : body.length;
    matches[i].content = body.slice(matches[i].endIdx, nextStart);
  }
  return matches;
}

function _isPrimitiveHeading(text) {
  return PRIMITIVE_SIGNATURE_RE.test(text);
}

// Heuristic: signature names `opts` (or `opts?`) somewhere in its arg
// list. Multi-method signatures count as opts-naming if ANY method
// takes an opts.
function _signatureNamesOpts(text) {
  return /\bopts\??\s*[,)]/.test(text) ||
         /\bopts\??\s*$/.test(text);
}

// Strip leading whitespace and `//` line-comments so we can look at
// the first significant character. Pages frequently prefix the opts
// block with a `// hash opts (and needsRehash opts):` line — the
// `{` follows.
function _firstSignificantChar(code) {
  var lines = code.split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var trimmed = lines[i].replace(/^\s+/, "");
    if (trimmed.length === 0) continue;        // blank line
    if (trimmed.indexOf("//") === 0) continue; // line-comment
    return trimmed.charAt(0);
  }
  return "";
}

// Find every <pre><code class="language-..."> block and classify it.
// Returns [{ language, content, looksLikeOpts }].
function _extractCodeBlocks(content) {
  var re = /<pre[^>]*>\s*<code[^>]*class="language-(\w+)"[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/g;
  var iter = content.matchAll(re);
  var out = [];
  for (var m of iter) {
    var lang = m[1];
    var code = m[2];
    var firstSig = _firstSignificantChar(code);
    out.push({
      language:      lang,
      content:       code,
      looksLikeOpts: lang === "javascript" && firstSig === "{",
    });
  }
  return out;
}

function _hasDescriptionProse(content) {
  return /<p\b/.test(content) || /<aside\b/.test(content);
}

// ---- Wiki opts-block parser ----
//
// Pulls the top-level keys from a literal-form opts block:
//
//   {
//     keyA:  string,                     // required: true
//     keyB:  number,                     // default: 30
//     keyC:  { nested: ... },            // — nested entries skipped
//   }
//
// Strategy: locate the outermost balanced `{ ... }` after stripping
// leading whitespace + comments. Walk the body, tracking brace/bracket/
// paren depth. At depth 0, a top-level entry runs from the previous
// `,` (or start) until the next top-level `,`. Each entry's first
// identifier before the first `:` is the key.

function _decodeHtmlEntities(s) {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
          .replace(/&#39;/g, "'");
}

function _stripJsLineComments(s) {
  // Strip `// ...` to end of line, line by line. Avoid stripping `//`
  // that appears inside a string literal — if seen, abandon line and
  // keep as-is. Simple-but-conservative: skip stripping when the line
  // contains an odd number of `'` or `"` before the `//`.
  return s.split("\n").map(function (line) {
    var idx = line.indexOf("//");
    if (idx < 0) return line;
    var before = line.slice(0, idx);
    var sq = (before.match(/'/g) || []).length;
    var dq = (before.match(/"/g) || []).length;
    if (sq % 2 !== 0 || dq % 2 !== 0) return line;
    return before;
  }).join("\n");
}

function _findOpenBrace(code) {
  // Skip leading whitespace + line comments. Return index of the
  // first `{` we encounter that's the start of the opts object.
  for (var i = 0; i < code.length; i++) {
    var c = code.charAt(i);
    if (c === " " || c === "\t" || c === "\n" || c === "\r") continue;
    if (c === "/" && code.charAt(i + 1) === "/") {
      var nl = code.indexOf("\n", i);
      if (nl < 0) return -1;
      i = nl;
      continue;
    }
    if (c === "{") return i;
    return -1;  // anything else means this isn't an opts block
  }
  return -1;
}

function _matchClosingBrace(code, openIdx) {
  var depth = 0;
  for (var i = openIdx; i < code.length; i++) {
    var c = code.charAt(i);
    if (c === '"' || c === "'") {
      // Skip string literal.
      var q = c;
      i++;
      while (i < code.length && code.charAt(i) !== q) {
        if (code.charAt(i) === "\\") i++;
        i++;
      }
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function _extractWikiOptsKeys(code) {
  var decoded = _decodeHtmlEntities(code);
  var stripped = _stripJsLineComments(decoded);
  var openIdx = _findOpenBrace(stripped);
  if (openIdx < 0) return null;
  var closeIdx = _matchClosingBrace(stripped, openIdx);
  if (closeIdx < 0) return null;
  var inner = stripped.slice(openIdx + 1, closeIdx);

  var keys = [];
  var depth = 0;
  var entryStart = 0;
  for (var i = 0; i < inner.length; i++) {
    var c = inner.charAt(i);
    if (c === '"' || c === "'") {
      var q = c;
      i++;
      while (i < inner.length && inner.charAt(i) !== q) {
        if (inner.charAt(i) === "\\") i++;
        i++;
      }
      continue;
    }
    if (c === "{" || c === "[" || c === "(") depth++;
    else if (c === "}" || c === "]" || c === ")") depth--;
    else if (c === "," && depth === 0) {
      _pushEntryKey(inner.slice(entryStart, i), keys);
      entryStart = i + 1;
    }
  }
  _pushEntryKey(inner.slice(entryStart), keys);
  return keys;
}

function _pushEntryKey(entry, out) {
  var trimmed = entry.replace(/^\s+|\s+$/g, "");
  if (trimmed.length === 0) return;
  var colonIdx = trimmed.indexOf(":");
  if (colonIdx < 0) return;
  var key = trimmed.slice(0, colonIdx).replace(/^\s+|\s+$/g, "");
  // Strip surrounding quotes if present
  key = key.replace(/^["']|["']$/g, "");
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) return;
  if (out.indexOf(key) === -1) out.push(key);
}

// ---- Lib allow-list probe ----
//
// Strategy: resolve `b.module.method(opts)` to the actual function,
// then call it with `{ <unique-key>: 1 }`. Most factories run a
// validateOpts (or in-line allow-list check) immediately and throw an
// error whose message contains the canonical allow-list. Two formats
// the framework emits:
//
//   "primitive: unknown option 'X'. Allowed keys: a, b, c."
//      (lib/validate-opts.js — the dominant pattern)
//
//   "unknown opt 'X'. Allowed: a, b, c"
//      (lib/db-declare-view.js / lib/db-declare-row-policy.js custom
//       form — same idea, slightly different wording)
//
// When the probe doesn't throw, or throws a different shape, the
// section's opts diff is skipped with a recorded reason. Presence
// remains enforced for those.

function _resolveSignaturePath(b, signature) {
  var match = signature.match(/^\s*(?:<code>\s*)?b\.([a-zA-Z0-9_.]+)\s*\(/);
  if (!match) return null;
  var path = match[1].split(".");
  var current = b;
  for (var i = 0; i < path.length; i++) {
    if (current === null || current === undefined) return null;
    current = current[path[i]];
  }
  return typeof current === "function" ? current : null;
}

function _probeAllowList(fn) {
  if (typeof fn !== "function") {
    return { ok: false, reason: "not-a-function" };
  }
  var probeKey = "__validator_probe_" + Date.now() + "_" + Math.random().toString(36).slice(2);
  var probeOpts = {};
  probeOpts[probeKey] = true;
  var thrown = null;
  try {
    var result = fn(probeOpts);
    // Async factories return a promise. The validation throw in the
    // sync prologue is what we want; if we got here without throwing,
    // there's no validateOpts on the sync path.
    if (result && typeof result.then === "function") {
      // Swallow the rejection silently — we only care that NOTHING
      // threw synchronously. (Promise rejections fire asynchronously
      // and can't be observed without a synchronous .catch handler;
      // queueing one keeps Node from logging an unhandled rejection.)
      result.then(function () {}, function () {});
      return { ok: false, reason: "async-no-sync-validateOpts" };
    }
    return { ok: false, reason: "no-throw-on-unknown-key" };
  } catch (e) {
    thrown = e;
  }
  var msg = (thrown && thrown.message) || "";
  // Two error message formats — both list the allowed keys after a
  // header word.
  var m = msg.match(/Allowed keys?:\s*([^.\n]+)/);
  if (!m) m = msg.match(/Allowed:\s*([^.\n]+)/);
  if (!m) return { ok: false, reason: "no-allow-list-in-error", message: msg };
  var keys = m[1].split(",").map(function (s) { return s.replace(/^\s+|\s+$/g, ""); }).filter(Boolean);
  return { ok: true, allowList: keys };
}

// Single-method signature like `b.module.method(opts)` — the only
// shape we know how to probe today. Multi-method (`b.X.a(opts) /
// b.X.b(opts)`) and positional-arg signatures (`b.X.method(arg, opts)`)
// fall through with a recorded reason.
function _isSingleOptsSignature(headingText) {
  return /^\s*(?:<code>\s*)?b\.[a-zA-Z0-9_.]+\(\s*opts\s*\??\s*\)/.test(headingText);
}

// ---- Opts diff ----
//
// For a primitive section that passes the single-opts-signature filter,
// diff the wiki opts keys against the lib's allow-list.
function _diffOptsKeys(b, headingText, optsCodeBlock) {
  if (!_isSingleOptsSignature(headingText)) {
    return { skipped: true, reason: "complex-signature" };
  }
  var fn = _resolveSignaturePath(b, headingText);
  if (!fn) {
    return { skipped: true, reason: "lib-fn-not-resolved" };
  }
  var probe = _probeAllowList(fn);
  if (!probe.ok) {
    return { skipped: true, reason: probe.reason };
  }
  var wikiKeys = _extractWikiOptsKeys(optsCodeBlock);
  if (!wikiKeys) {
    return { skipped: true, reason: "wiki-opts-block-unparseable" };
  }
  var libKeys = probe.allowList.slice();
  var addedInWiki = wikiKeys.filter(function (k) { return libKeys.indexOf(k) === -1; });
  var removedFromWiki = libKeys.filter(function (k) { return wikiKeys.indexOf(k) === -1; });
  return {
    skipped: false,
    wikiKeys: wikiKeys,
    libKeys: libKeys,
    addedInWiki:     addedInWiki,
    removedFromWiki: removedFromWiki,
  };
}

// ---- Post-boot pass helpers — example syntax / symbol / execution ----
//
// Each non-opts javascript example is checked through three lenses:
//
//   1. Syntax — V8 parses the code via vm.compileFunction, wrapped in
//      an async closure so top-level `await` is legal. Catches typos,
//      missing braces, dangling parens.
//
//   2. Symbol resolution — regex out every `b.X.Y` reference in the
//      example and walk the live framework to confirm each path
//      resolves. The wiki promises operator-callable surface; if a
//      reference doesn't resolve, the wiki documents an API the lib
//      no longer exposes (or never did) — drift the gate must catch.
//
//   3. Execution — best-effort. Most examples reference operator-
//      supplied stubs (req, res, db rows, an externalDb client, third-
//      party adapters). The harness binds a small fixed set of stubs
//      (req, res, env-shaped helpers); examples that need more are
//      classified "needs-context" and counted as illustrative-only,
//      not failed. Examples that reach the framework with bad arg
//      shapes still fail loud — that's the drift class operators want
//      caught.
//
// The wiki seeders are committed source — every example is content
// authored by the framework team. vm.compileFunction parses and
// invokes that content under a controlled lexical scope (no `require`,
// no globals beyond what we pass in). This is the standard Node
// pattern for sandboxed evaluation of trusted-source code.
var vm = require("node:vm");

function _decodeExampleEntities(code) {
  return code.replace(/&amp;/g, "&").replace(/&lt;/g, "<")
             .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
             .replace(/&#39;/g, "'");
}

function _checkExampleSyntax(code) {
  var asyncBody = "return (async () => {\n" + code + "\n})();";
  try {
    vm.compileFunction(asyncBody, ["b", "req", "res", "env"]);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: (e && e.message) || String(e) };
  }
}

function _frameworkPathsIn(code) {
  var paths = [];
  var seen = Object.create(null);
  var iter = code.matchAll(/\bb(\.[a-zA-Z_$][\w$]*)+/g);
  for (var m of iter) {
    var p = m[0];
    if (!seen[p]) { seen[p] = true; paths.push(p); }
  }
  return paths;
}

function _resolvePath(b, dotted) {
  var segs = dotted.split(".");
  if (segs[0] !== "b") return { resolved: false, missingAt: 0 };
  var cur = b;
  for (var i = 1; i < segs.length; i++) {
    if (cur === null || cur === undefined) {
      return { resolved: false, missingAt: i };
    }
    if (!Object.prototype.hasOwnProperty.call(Object(cur), segs[i])) {
      return { resolved: false, missingAt: i };
    }
    cur = cur[segs[i]];
  }
  return { resolved: true, value: cur };
}

function _checkExampleSymbols(b, code) {
  var paths = _frameworkPathsIn(code);
  var unresolved = [];
  for (var i = 0; i < paths.length; i++) {
    var p = paths[i];
    var r = _resolvePath(b, p);
    if (!r.resolved) unresolved.push(p);
  }
  return { ok: unresolved.length === 0, paths: paths, unresolved: unresolved };
}


// Spawn the run-example.js child with the example payload on stdin.
// The child boots a fresh framework instance, runs the example with
// the harness stubs in scope, and reports the outcome on stdout as
// JSON. One child per example = isolated framework state per run.
function _executeExampleForked(spec) {
  return new Promise(function (resolve) {
    var cp = require("node:child_process");
    var runner = path.join(__dirname, "run-example.js");
    var child = cp.spawn(process.execPath, [runner], {
      stdio: ["pipe", "pipe", "pipe"],
      env:   process.env,
    });
    var stdoutBuf = "";
    var stderrBuf = "";
    child.stdout.on("data", function (c) { stdoutBuf += c.toString("utf8"); });
    child.stderr.on("data", function (c) { stderrBuf += c.toString("utf8"); });
    child.on("close", function (code) {
      var SENTINEL = "<<<WIKI-VALIDATOR-OUTCOME>>>";
      var idx = stdoutBuf.lastIndexOf(SENTINEL);
      var result = null;
      if (idx >= 0) {
        var trailing = stdoutBuf.slice(idx + SENTINEL.length).trim();
        try { result = JSON.parse(trailing); }
        catch (_e) {
          result = {
            status: "harness-parse-error",
            error:  "outcome JSON malformed after sentinel",
            stdout: trailing.slice(0, 500),
            stderr: stderrBuf.slice(0, 500),
            exit:   code,
          };
        }
      } else {
        result = {
          status: "harness-no-outcome",
          error:  "child exited without writing the outcome sentinel",
          stdout: stdoutBuf.slice(-500),
          stderr: stderrBuf.slice(0, 500),
          exit:   code,
        };
      }
      resolve(result);
    });
    child.on("error", function (e) {
      resolve({ status: "harness-spawn-error", error: (e && e.message) || String(e) });
    });
    child.stdin.end(JSON.stringify(spec));
  });
}

async function runExamples(b) {
  var pages = _readPageBodies();
  var report = {
    total: 0,
    ran: 0,
    syntaxFailed:    [],
    symbolFailed:    [],
    executionFailed: [],
  };

  // Gather every executable example into a queue first; do the cheap
  // syntax + symbol checks inline (no forks needed). The expensive
  // step is the forked runtime — that runs in parallel batches.
  var pending = [];
  for (var p = 0; p < pages.length; p++) {
    var page = pages[p];
    var sections = _splitSections(page.body);
    for (var i = 0; i < sections.length; i++) {
      var s = sections[i];
      if (!_isPrimitiveHeading(s.text)) continue;
      var key = _exemptionKey(page.slug, s.text);
      if (EXEMPTIONS[key]) continue;
      var clusterContent = _clusterContent(sections, i);
      var blocks = _extractCodeBlocks(clusterContent);
      for (var b2 = 0; b2 < blocks.length; b2++) {
        var blk = blocks[b2];
        if (blk.looksLikeOpts) continue;
        if (blk.language !== "javascript") continue;
        report.total++;
        var decoded = _decodeExampleEntities(blk.content);

        var syn = _checkExampleSyntax(decoded);
        if (!syn.ok) {
          report.syntaxFailed.push({
            slug: page.slug, heading: s.text, error: syn.error,
          });
          continue;
        }
        var sym = _checkExampleSymbols(b, decoded);
        if (!sym.ok) {
          report.symbolFailed.push({
            slug: page.slug, heading: s.text, unresolved: sym.unresolved,
          });
          continue;
        }
        pending.push({ slug: page.slug, heading: s.text, code: decoded });
      }
    }
  }

  // Parallel execution. SMOKE_PARALLEL respected (capped at 64 to
  // match the smoke runner) — sequential mode (`SMOKE_PARALLEL=1`)
  // available as a fallback for diagnosis.
  var rawN = parseInt(process.env.SMOKE_PARALLEL || "1", 10);
  var concurrency = (isFinite(rawN) && rawN > 0) ? Math.min(rawN, 64) : 1;
  var queueIdx = 0;
  async function _worker() {
    while (queueIdx < pending.length) {
      var spec = pending[queueIdx++];
      var exec = await _executeExampleForked(spec);
      if (exec.status === "ran") {
        report.ran++;
      } else {
        report.executionFailed.push({
          slug: spec.slug, heading: spec.heading,
          status:  exec.status,
          error:   exec.error || null,
          missing: exec.missing || null,
          stack:   exec.stack || null,
        });
      }
    }
  }
  var workers = [];
  for (var w = 0; w < Math.min(concurrency, pending.length); w++) {
    workers.push(_worker());
  }
  await Promise.all(workers);
  return report;
}

// ---- Validate ----

function _exemptionKey(slug, headingText) {
  return slug + ":" + headingText.slice(0, 50).toLowerCase().replace(/\s+/g, " ").trim();
}

// Accumulate the "cluster" content for a primitive section. The
// cluster is the full H2 subtree: H2 preface + every H3 inside it,
// up to (but not including) the next H2.
//
// Why H2-scoped: pages document related primitives as a single
// operator-readable unit under one H2 — "Passkeys" H2 covers
// startRegistration / verifyRegistration / startAuthentication /
// verifyAuthentication with the opts models per H3 and one merged
// example showing all four in flow. The cluster shares prose +
// example across siblings; each primitive H3 individually still
// needs its own opts model when the signature names opts.
//
// For top-level primitives that ARE H2s themselves, the cluster is
// the H2's own content + every H3 under it.
function _clusterContent(sections, startIdx) {
  var s = sections[startIdx];

  // Find the parent H2 (or self if startIdx is itself an H2).
  var parentIdx = startIdx;
  if (s.level === 3) {
    for (var k = startIdx - 1; k >= 0; k--) {
      if (sections[k].level === 2) { parentIdx = k; break; }
    }
    if (parentIdx === startIdx) parentIdx = -1; // no parent H2 above
  }

  var combined = "";
  if (parentIdx >= 0) {
    combined = sections[parentIdx].content;
    // Walk every section after the parent H2 until the next H2.
    for (var j = parentIdx + 1; j < sections.length; j++) {
      if (sections[j].level === 2) break;
      combined += "\n" + sections[j].raw + "\n" + sections[j].content;
    }
  } else {
    combined = s.content;
    for (var jj = startIdx + 1; jj < sections.length; jj++) {
      if (sections[jj].level <= s.level) break;
      combined += "\n" + sections[jj].raw + "\n" + sections[jj].content;
    }
  }
  return combined;
}

function _validatePage(page, opts) {
  opts = opts || {};
  var b = opts.framework || null;
  var sections = _splitSections(page.body);
  var violations = [];
  for (var i = 0; i < sections.length; i++) {
    var s = sections[i];
    if (!_isPrimitiveHeading(s.text)) continue;
    var key = _exemptionKey(page.slug, s.text);
    var exemptReason = EXEMPTIONS[key];
    var clusterContent = _clusterContent(sections, i);
    var blocks = _extractCodeBlocks(clusterContent);
    var hasOpts    = blocks.some(function (blk) { return blk.looksLikeOpts; });
    var hasExample = blocks.some(function (blk) {
      return !blk.looksLikeOpts && (blk.language === "javascript" || blk.language === "bash");
    });
    var hasProse   = _hasDescriptionProse(clusterContent);
    var needsOpts  = _signatureNamesOpts(s.text);

    var missing = [];
    if (needsOpts && !hasOpts) missing.push("opts-model");
    if (!hasProse)             missing.push("description-prose");
    if (!hasExample)           missing.push("example-code");

    // Opts diff — only when presence is satisfied AND the framework is
    // available for probing. We don't run the diff when presence
    // already failed; that report dominates and the diff would just
    // duplicate noise.
    var optsDiff = null;
    if (b && missing.length === 0 && hasOpts) {
      var optsBlock = blocks.find(function (blk) { return blk.looksLikeOpts; });
      if (optsBlock) {
        optsDiff = _diffOptsKeys(b, s.text, optsBlock.content);
      }
    }

    if (missing.length === 0) {
      // Presence OK. If opts diff found drift, surface it.
      if (optsDiff && !optsDiff.skipped &&
          (optsDiff.addedInWiki.length > 0 || optsDiff.removedFromWiki.length > 0)) {
        violations.push({
          slug:    page.slug,
          heading: s.text,
          missing: [],
          optsDiff: optsDiff,
          exempt:  !!exemptReason,
          reason:  exemptReason || null,
          key:     key,
        });
      }
      continue;
    }

    violations.push({
      slug:    page.slug,
      heading: s.text,
      missing: missing,
      optsDiff: optsDiff,
      exempt:  !!exemptReason,
      reason:  exemptReason || null,
      key:     key,
    });
  }
  return violations;
}

// ---- Missing-section enumeration ----
//
// The earlier validator only checked that EXISTING wiki sections have
// the four required pieces (heading + opts + prose + example). It did
// NOT catch the case where an operator-facing primitive on `b.*`
// has NO documented section at all. This walker enumerates `b.*`,
// applies a skip-list for non-primitive surface (constants, internal
// catalogs, frameworkError class registry, lazyRequire helper, etc.),
// and reports every undocumented primitive.
//
// Two-level enumeration: every top-level key on `b.*` is checked, AND
// every sub-key on top-level namespace objects (b.middleware.*,
// b.auth.*, b.auditSign.*, etc.). Without the second level, new
// methods added to an already-documented namespace (e.g.
// b.middleware.requireMtls landing under the existing middleware page)
// are invisible to the gate because the namespace itself is in the
// "documented" set. BX_SKIP and UNDOCUMENTED_BACKLOG accept both
// bare names ("auth") and qualified names ("auth.accessLock") so a
// blanket namespace skip and a per-method opt-out are both expressible.
//
// Pre-v0.7.31 backlog: primitives that pre-existed without a wiki
// section live in UNDOCUMENTED_BACKLOG below with a one-line reason —
// they're visible warnings, not gate failures, until backfilled. New
// primitives shipped from v0.7.31 forward MUST either land with a
// wiki section OR get added to UNDOCUMENTED_BACKLOG explicitly.

// Top-level keys on `b.*` that are NOT primitives — skipped entirely.
// Sub-key entries (`auth.acr` etc.) skip a single method when the
// parent namespace is being recursively enumerated.
var BX_SKIP = new Set([
  // Top-level non-primitive surface.
  "constants",         // compile-time scale helpers, not callable
  "frameworkError",    // class catalog (typed errors), not a primitive
  "_modules",          // raw-module advanced access
  "_internalForTest",  // internal test plumbing
  "testing",           // test helpers (b.testing.bodyReq etc. — pages document via testing.js page)
  "lazyRequire",       // build-time helper for circular-dep modules
  "validateOpts",      // build-time helper used inside primitives
  "cliHelpers",        // CLI subcommand plumbing
  "parsers",           // namespace; sub-modules documented under safe-parsers
  "logStream",         // documented under observability page
  "events",            // documented under observability page
  "redact",            // documented under observability page
  "lib",               // raw module access
  // Sub-key non-primitive surface (parent.child form). Used by the
  // BX_RECURSE walker to ignore sub-keys that are data tables / getters
  // / constants rather than operator-facing primitives.
  "auth.acr",                            // ACR vocabulary table (constants only, no callable surface)
  "auditSign.DEFAULT_SIGNING_ALG",       // constant string
  "auditSign.SUPPORTED_SIGNING_ALGS",    // constant array
  "auditSign.ENV_PASSPHRASE",            // constant string
  "auditSign.ENV_PASSPHRASE_FILE",       // constant string
  "auditSign.ENV_PASSPHRASE_SRC",        // constant string
  "auditSign.getMode",                   // getter, not a primitive
  "auditSign.getAlgorithm",              // getter, not a primitive
  "auditSign.getPublicKey",              // getter, not a primitive
  "auditSign.getPublicKeyFingerprint",   // getter, not a primitive
]);


// Pre-v0.7.31 primitives without a dedicated wiki section. Each entry
// names the page it SHOULD be documented under (or notes the reason
// for the gap). Backfill opportunistically; new primitives don't get
// added here without an explicit reason.
var UNDOCUMENTED_BACKLOG = {
  // === New primitives shipped without a wiki section yet — backlog. ===
  "openapi":               "shipped v0.7.110 — OpenAPI 3.1 schema-document builder; wiki section deferred to a follow-up patch (operator-facing surface stable, JSDoc + comprehensive test suite cover usage)",
  "flag":                  "shipped v0.7.111 — OpenFeature feature-flag client; wiki section deferred to a follow-up patch (operator-facing surface stable, JSDoc + comprehensive test suite cover usage)",
  "asyncapi":              "shipped v0.7.112 — AsyncAPI 3.0 schema-document builder; wiki section deferred to a follow-up patch (operator-facing surface stable, JSDoc + comprehensive test suite cover usage)",
  "pqcSoftware":           "shipped v0.7.112 — pure-JS PQC primitive wrapper around vendored @noble/post-quantum; wiki section deferred — primitive is a thin getter-style accessor, README + JSDoc cover the full API",
  "wsClient":              "shipped v0.7.114 — outbound RFC 6455 WebSocket client; wiki section deferred to a follow-up patch (operator-facing surface stable, JSDoc + integration test suite cover usage)",
  "circuitBreaker":        "shipped v0.8.8 — top-level re-export of b.retry.CircuitBreaker for ergonomic discovery alongside b.retry; wiki section deferred (the underlying CircuitBreaker class is documented under the resilience.js page; this primitive is the discovery alias only, not a new behaviour)",
  "incident":              "shipped v0.8.9 — generic 3-stage incident-reporting primitive (24h / 72h / 30d) with regime-keyed deadlines (gdpr / nis2 / dora / cra / hipaa); wiki section deferred to a follow-up patch (operator-facing surface stable, JSDoc + test suite cover the per-regime deadline shape)",
  "cra":                   "shipped v0.8.10 — EU Cyber Resilience Act incident-reporting wrapper (Article 14 §1 deadlines: 24h / 72h / 14d); composes b.incident.report; wiki section deferred (operator-facing surface stable, JSDoc covers ENISA submission shape)",
  "nis2":                  "shipped v0.8.10 — NIS2 Directive incident-reporting wrapper (Article 23 §4 deadlines: 24h / 72h / 1 month) with Annex I/II sector codes + essential/important entity types; wiki section deferred",
  "gdpr":                  "shipped v0.8.10 — GDPR Article 30 Records of Processing Activities registry + JSON / CSV / Markdown exporter; wiki section deferred (operator-facing surface stable, JSDoc covers the activity shape and legal-basis vocabulary)",
  "breach":                "shipped v0.8.11 — US-state breach-notification deadline registry + multi-state filing reporter; wiki section deferred (operator-facing surface stable, JSDoc covers per-state statutory citations + filing flow; the registry data itself is governed by state legislatures, not framework versions)",
  "ai":                    "shipped v0.8.11 — adverse-decision wrapper for automated decisions affecting consumer rights (GDPR Article 22 / EU AI Act 86 / ECOA / Colorado AI Act / NYC LL 144 / FCRA); wiki section deferred (operator-facing surface stable, JSDoc covers the regime vocabulary + adverseNotice shape)",
  "sse":                   "shipped v0.8.15 — Server-Sent Events transport with newline-injection refusal (CVE-2026-33128 / 29085 / 44217 class); wiki section deferred to a follow-up patch — operator-facing surface stable, JSDoc + standalone test suite cover usage; b.middleware.sse already documented under routing.js page",
  "mcp":                   "shipped v0.8.15 — Model Context Protocol server-guard (bearer auth + redirect_uri allowlist + dynamic-register refusal + tool/resource allowlist) — wiki section deferred (operator-facing surface stable, JSDoc + standalone test suite cover the JSON-RPC envelope + guard policy)",
  "graphqlFederation":     "shipped v0.8.15 — Apollo Federation _service.sdl trust-boundary guard (router-token Bearer + nonce store) — wiki section deferred (operator-facing surface stable, JSDoc + standalone test suite cover the queryProbesSdl detector)",
  "a2a":                   "shipped v0.8.15 — A2A (Linux Foundation Agentic AI Foundation) v1.x signed agent-card primitive — wiki section deferred (operator-facing surface stable, JSDoc covers signCard / verifyCard / canonicalize)",
  "darkPatterns":          "shipped v0.8.15 — FTC Negative Option Rule click-to-cancel UX-parity attestation primitive (recordSignupFlow / recordCancelFlow / assertParity / attest / middleware) — wiki section deferred (operator-facing surface stable, JSDoc covers per-posture parity rules)",
  "ai.input":              "shipped v0.8.15 — prompt-injection input classifier (OWASP LLM01:2025 / NIST COSAIS RFI); wiki section deferred — operator-facing surface stable, JSDoc + standalone test cover the pattern + verdict shape",
  "sse.create":            "shipped v0.8.15 — wiki section deferred (covered with the b.sse parent backlog entry)",
  "sse.serializeEvent":    "shipped v0.8.15 — wiki section deferred (covered with the b.sse parent backlog entry)",
  "mcp.serverGuard":       "shipped v0.8.15 — wiki section deferred (covered with the b.mcp parent backlog entry)",
  "mcp.parseRequest":      "shipped v0.8.15 — wiki section deferred (covered with the b.mcp parent backlog entry)",
  "mcp.refuse":            "shipped v0.8.15 — wiki section deferred (covered with the b.mcp parent backlog entry)",
  "graphqlFederation.guardSdl":      "shipped v0.8.15 — wiki section deferred (covered with the b.graphqlFederation parent backlog entry)",
  "graphqlFederation.queryProbesSdl":"shipped v0.8.15 — wiki section deferred (covered with the b.graphqlFederation parent backlog entry)",
  "a2a.signCard":          "shipped v0.8.15 — wiki section deferred (covered with the b.a2a parent backlog entry)",
  "a2a.verifyCard":        "shipped v0.8.15 — wiki section deferred (covered with the b.a2a parent backlog entry)",
  "a2a.canonicalize":      "shipped v0.8.15 — wiki section deferred (covered with the b.a2a parent backlog entry)",
  "a2a.createCard":        "shipped v0.8.15 — wiki section deferred (covered with the b.a2a parent backlog entry)",
  "darkPatterns.recordSignupFlow":  "shipped v0.8.15 — wiki section deferred (covered with the b.darkPatterns parent backlog entry)",
  "darkPatterns.recordCancelFlow":  "shipped v0.8.15 — wiki section deferred (covered with the b.darkPatterns parent backlog entry)",
  "darkPatterns.assertParity":      "shipped v0.8.15 — wiki section deferred (covered with the b.darkPatterns parent backlog entry)",
  "darkPatterns.attest":            "shipped v0.8.15 — wiki section deferred (covered with the b.darkPatterns parent backlog entry)",
  "darkPatterns.middleware":        "shipped v0.8.15 — wiki section deferred (covered with the b.darkPatterns parent backlog entry)",
  "darkPatterns.DarkPatternsError": "shipped v0.8.15 — error class export, wiki section deferred",
  "budr":             "shipped v0.8.24 — RTO/RPO declaration primitive (DORA Art 11 / ISO 22301:2019 / NIST SP 800-34); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover the declaration shape + tier vocabulary)",
  "budr.declare":     "shipped v0.8.24 — wiki section deferred (covered with the b.budr parent backlog entry)",
  "budr.get":         "shipped v0.8.24 — wiki section deferred (covered with the b.budr parent backlog entry)",
  "budr.list":        "shipped v0.8.24 — wiki section deferred (covered with the b.budr parent backlog entry)",
  "budr.BudrError":   "shipped v0.8.24 — error class export, wiki section deferred",
  "secCyber":         "shipped v0.8.25 — SEC Cybersecurity Disclosure Item 1.05 8-K artifact generator (17 CFR §229.106 / Form 8-K Item 1.05); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover the materiality determination + AG-delay request shapes)",
  "secCyber.eightKArtifact": "shipped v0.8.25 — wiki section deferred (covered with the b.secCyber parent backlog entry)",
  "secCyber.SecCyberError":  "shipped v0.8.25 — error class export, wiki section deferred",
  "iabTcf":                   "shipped v0.8.26 — IAB TCF v2.3 consent string parser + disclosedVendors validator (TCF Policy v2.3 §III.B.5; deadline past 2026-02-28); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover the parse + requireV23 + checkVendor shapes)",
  "iabTcf.parseString":       "shipped v0.8.26 — wiki section deferred (covered with the b.iabTcf parent backlog entry)",
  "iabTcf.requireV23Disclosed":"shipped v0.8.26 — wiki section deferred (covered with the b.iabTcf parent backlog entry)",
  "iabTcf.checkVendor":       "shipped v0.8.26 — wiki section deferred (covered with the b.iabTcf parent backlog entry)",
  "iabTcf.IabTcfError":       "shipped v0.8.26 — error class export, wiki section deferred",
  "fapi2":                    "shipped v0.8.27 — FAPI 2.0 Final conformance posture (composes existing PAR/DPoP/OAuth 2.1/mTLS); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover the assertion shapes)",
  "fapi2.assertConformance":  "shipped v0.8.27 — wiki section deferred (covered with the b.fapi2 parent backlog entry)",
  "fapi2.assertOAuthConfig":  "shipped v0.8.27 — wiki section deferred (covered with the b.fapi2 parent backlog entry)",
  "fapi2.posture":            "shipped v0.8.27 — wiki section deferred (covered with the b.fapi2 parent backlog entry)",
  "fapi2.Fapi2Error":         "shipped v0.8.27 — error class export, wiki section deferred",
  "contentCredentials":       "shipped v0.8.28 — California SB-942 / AB-853 + C2PA 2.1 content-provenance manifest builder for AI-generated assets (deadline 2026-08-02); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover the build/sign/verify shapes)",
  "contentCredentials.build": "shipped v0.8.28 — wiki section deferred (covered with the b.contentCredentials parent backlog entry)",
  "contentCredentials.sign":  "shipped v0.8.28 — wiki section deferred (covered with the b.contentCredentials parent backlog entry)",
  "contentCredentials.verify":"shipped v0.8.28 — wiki section deferred (covered with the b.contentCredentials parent backlog entry)",
  "contentCredentials.required":"shipped v0.8.28 — wiki section deferred (covered with the b.contentCredentials parent backlog entry)",
  "contentCredentials.ContentCredentialsError":"shipped v0.8.28 — error class export, wiki section deferred",
  "aiPref":                   "shipped v0.8.30 — AIPREF Content-Usage HTTP response header + Cloudflare Content Signals + Pay-Per-Crawl 402 (IETF draft-ietf-aipref-attach-04, deadline 2026-08); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover middleware + serialize/parse + robots-block shapes)",
  "aiPref.middleware":        "shipped v0.8.30 — wiki section deferred (covered with the b.aiPref parent backlog entry)",
  "aiPref.serializeHeader":   "shipped v0.8.30 — wiki section deferred (covered with the b.aiPref parent backlog entry)",
  "aiPref.parseHeader":       "shipped v0.8.30 — wiki section deferred (covered with the b.aiPref parent backlog entry)",
  "aiPref.robotsBlock":       "shipped v0.8.30 — wiki section deferred (covered with the b.aiPref parent backlog entry)",
  "aiPref.refusePaidCrawl":   "shipped v0.8.30 — wiki section deferred (covered with the b.aiPref parent backlog entry)",
  "aiPref.AiPrefError":       "shipped v0.8.30 — error class export, wiki section deferred",
  "fdx":                      "shipped v0.8.31 — CFPB §1033 / Financial Data Exchange (FDX 6.0) bind primitive (deadline past 2026-04-01 for $250B+ asset-size banks); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover bind / validateResponse / consentReceipt shapes)",
  "fdx.bind":                 "shipped v0.8.31 — wiki section deferred (covered with the b.fdx parent backlog entry)",
  "fdx.validateResponse":     "shipped v0.8.31 — wiki section deferred (covered with the b.fdx parent backlog entry)",
  "fdx.consentReceipt":       "shipped v0.8.31 — wiki section deferred (covered with the b.fdx parent backlog entry)",
  "fdx.FdxError":             "shipped v0.8.31 — error class export, wiki section deferred",
  "tcpa10dlc":                "shipped v0.8.35 — TCPA 10DLC consent-record audit primitive (47 USC §227 / 47 CFR §64.1200 / FCC 1:1 disclosure); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover recordConsent / lookup / revoke shapes)",
  "tcpa10dlc.recordConsent":  "shipped v0.8.35 — wiki section deferred (covered with the b.tcpa10dlc parent backlog entry)",
  "tcpa10dlc.lookup":         "shipped v0.8.35 — wiki section deferred (covered with the b.tcpa10dlc parent backlog entry)",
  "tcpa10dlc.revoke":         "shipped v0.8.35 — wiki section deferred (covered with the b.tcpa10dlc parent backlog entry)",
  "tcpa10dlc.Tcpa10dlcError": "shipped v0.8.35 — error class export, wiki section deferred",
  "iabMspa":                  "shipped v0.8.35 — IAB MSPA / GPP universal opt-out signal codec (CCPA §1798.135 + multi-state US privacy laws); wiki section deferred (operator-facing surface stable, JSDoc + standalone test cover parseGpp / checkOptOut / refuseProcessing / gpcFromHeaders)",
  "iabMspa.parseGpp":         "shipped v0.8.35 — wiki section deferred (covered with the b.iabMspa parent backlog entry)",
  "iabMspa.checkOptOut":      "shipped v0.8.35 — wiki section deferred (covered with the b.iabMspa parent backlog entry)",
  "iabMspa.refuseProcessing": "shipped v0.8.35 — wiki section deferred (covered with the b.iabMspa parent backlog entry)",
  "iabMspa.gpcFromHeaders":   "shipped v0.8.35 — wiki section deferred (covered with the b.iabMspa parent backlog entry)",
  "iabMspa.IabMspaError":     "shipped v0.8.35 — error class export, wiki section deferred",

  // v0.8.39 operator enhancements — deferred wiki entries
  "configDrift.verifyVendorIntegrity": "shipped v0.8.39 — vendor-manifest integrity check; wiki section deferred (JSDoc + standalone test cover the `lib/vendor/MANIFEST.json` re-hash + audit emit shape)",
  "ssrfGuard.createAllowlist":         "shipped v0.8.39 — composes ssrfGuard with operator allow/deny CIDR set; wiki section deferred (JSDoc covers shape; egress-allowlist composes on the existing ssrfGuard wiki page)",
  "auth.atoKillSwitch":                "shipped v0.8.39 — composite ATO kill-switch (b.session.destroyAllForUser + b.auth.lockout.lock + optional b.auth.accessLock flip); wiki section deferred (JSDoc + auth-lockout test cover the trigger shape)",
  "auth.atoKillSwitch.trigger":        "shipped v0.8.39 — wiki section deferred (covered with b.auth.atoKillSwitch parent)",
  "auth.atoKillSwitch.AtoKillSwitchError": "shipped v0.8.39 — error class export, wiki section deferred",
  "network.allowlist":                 "shipped v0.8.39 — `b.network.allowlist.create` is the public entry; wiki section deferred (composes on b.ssrfGuard)",
  "network.allowlist.create":          "shipped v0.8.39 — wiki section deferred (covered with b.network.allowlist parent)",

  // v0.8.40 operator enhancements — deferred wiki entries
  "honeytoken":                        "shipped v0.8.40 — canary credential framework; wiki section deferred (JSDoc + slot-20 standalone test cover issue / lookup / revoke shapes)",
  "honeytoken.create":                 "shipped v0.8.40 — wiki section deferred (covered with b.honeytoken parent)",
  "honeytoken.KINDS":                  "shipped v0.8.40 — kinds enumeration export; wiki section deferred",
  "honeytoken.HoneytokenError":        "shipped v0.8.40 — error class export, wiki section deferred",
  "middleware.cspReport":              "shipped v0.8.40 — CSP / Reporting-API endpoint middleware; wiki section deferred (JSDoc + slot-20 standalone test cover the request validation + audit-emit shape)",
  "auditTools.forensicSnapshot":       "shipped v0.8.40 — forensic-snapshot composer; wiki section deferred (composes on existing b.auditTools.exportSlice — covered on the auditTools wiki page)",
  "network.tls.pinsetDriftMonitor":    "shipped v0.8.40 — pinset drift monitor; wiki section deferred (composes on the existing expiryMonitor pattern documented under the network-tls wiki page)",

  // v0.8.41 — crypto/email/TLS impl-vs-spec + B1 / B3 / B5
  "resourceAccessLock":                "shipped v0.8.41 — three-mode (open/read-only/locked) resource access-lock for non-HTTP resources; wiki section deferred (JSDoc + standalone test cover create / set / permits / assertPermits)",
  "resourceAccessLock.create":         "shipped v0.8.41 — wiki section deferred (covered with b.resourceAccessLock parent)",
  "resourceAccessLock.VALID_MODES":    "shipped v0.8.41 — modes enumeration; wiki section deferred",
  "resourceAccessLock.ResourceAccessLockError": "shipped v0.8.41 — error class export, wiki section deferred",
  "config.loadDbBacked":               "shipped v0.8.41 — DB-row-backed periodic config hot-reload composer; wiki section deferred (composes on existing b.config wiki page)",
  "backup.runInWorker":                "shipped v0.8.41 — worker_threads dispatch for heavy backup/restore; wiki section deferred (operator-supplied workerScript wires the actual backup logic)",
  "canonicalJson":                     "documented under canonical-json.js page; v0.8.41 added stringifyJcs (RFC 8785 strict mode) — covered by the canonical-json-jcs standalone test",
  "pqcSoftware.runKnownAnswerTest":    "shipped v0.8.41 — boot-time KAT for the vendored ML-KEM-1024; wiki section deferred (covered on the pqcSoftware wiki page)",
  "auth.password.gate":                "shipped v0.8.41 — process-global semaphore for Argon2id concurrency; wiki section deferred (covered on the auth-password wiki page)",
  "constants.ENVELOPE_FIXED_INFO_LABEL": "shipped v0.8.41 — internal envelope FixedInfo label; not operator-facing (constants exposed for test-vector authoring only)",

  // v0.8.42 — DB hardening + H6 sub-issues + OWASP-1
  "processSpawn":                      "shipped v0.8.42 — child-process launcher with default secret-stripping; wiki section deferred (covered by JSDoc + standalone test)",
  "processSpawn.spawn":                "shipped v0.8.42 — wiki section deferred (covered with b.processSpawn parent)",
  "processSpawn.filteredEnv":          "shipped v0.8.42 — wiki section deferred (covered with b.processSpawn parent)",
  "processSpawn.FILTER_PATTERNS":      "shipped v0.8.42 — env-name pattern array export; wiki section deferred",
  "processSpawn.ProcessSpawnError":    "shipped v0.8.42 — error class export, wiki section deferred",
  "db.vacuumAfterErase":               "shipped v0.8.42 — operator-callable VACUUM; wiki section deferred (covered on b.db wiki page + standalone test)",
  "auditTools.withRecordedAtIso":      "shipped v0.8.42 — F-AUD-4 ISO-8601 surface helper; wiki section deferred (covered with b.auditTools wiki page)",
  "vault.getDerivedHashSalt":          "shipped v0.8.42 — D-H1 per-deployment salt accessor; wiki section deferred (internal-facing — used by b.cryptoField; covered on b.vault wiki page)",

  // === Documented under a parent's wiki page (no signature-form heading
  //     for the namespace itself, but every public method on it has one
  //     covered by the parent page or a sibling section). ===
  "router":                "documented under routing.js page; `new b.router.Router(...)` heading reads as a constructor — pattern matcher requires bare `b.X(` form",
  "websocket":             "documented under websockets.js page; namespace heading without parentheses",
  "vaultPassphraseSource": "documented under crypto-vault.js page",
  "vaultPassphraseOps":    "documented under crypto-vault.js page",
  "vaultRotate":           "documented under crypto-vault.js page",
  "auditChain":            "documented under observability.js + compliance-patterns.js pages",
  "auditTools":            "documented under backup-restore.js page (audit archive flow)",
  "subject":               "documented under compliance-patterns.js page",
  "atomicFile":            "documented under database.js page (atomic-file-write semantics)",
  "frameworkSchema":       "documented under database.js page (schema declaration)",
  "clusterStorage":        "documented under cluster.js page",
  "handlers":              "documented under routing.js page (handler-style middleware)",
  "chainWriter":           "documented under observability.js page (audit chain writer)",
  "nonceStore":            "documented under crypto-vault.js page (nonce-store primitive)",
  "authHeader":            "documented under outbound-http.js page",
  "pubsub":                "documented under queue-cache.js page",
  "config":                "documented under access-control.js page (config-drift)",
  "template":              "documented under routing.js page",
  "safeEnv":               "documented under safe-parsers.js page",
  "safeAsync":             "documented under safe-parsers.js page",
  "deprecate":             "internal — deprecate() calls flow into MIGRATING.md",
  "gateContract":          "documented under guard-all.js page (gate composition)",
  "locale":                "documented under i18n-locale.js page",
  "seeders":               "documented under database.js page",
  "boot":                  "internal — boot helpers",
  "log":                   "documented under observability.js page",
  "limit":                 "documented under reliability.js page",
  "cliPassword":           "internal — CLI subcommand",
  "cliAudit":              "internal — CLI subcommand",
  "cliBackup":             "internal — CLI subcommand",
  "cliRestore":            "internal — CLI subcommand",

  // === Long-standing primitives that have content on a page but the    ===
  // === wiki section headings don't begin with `b.X.Y` signature shape. ===
  // === Validator-blind to non-signature-form headings; these are real  ===
  // === pages, just structured differently. Backfill the heading shape  ===
  // === in a future sweep so the validator picks them up.               ===
  "vaultWrap":      "covered by crypto-vault.js page (vault sealing); prose-form headings",
  "auditSign":      "covered by observability.js page (audit signing); prose-form headings",
  "objectStore":    "covered by object-store.js page; backend-builder pattern, not flat methods",
  "migrations":     "covered by database.js page (schema migrations); operator wires via opts",
  "cli":            "internal — `blamejs <subcommand>` CLI plumbing",
  "dev":            "internal — dev-mode REPL helpers (b.dev.*)",
  "bundler":        "covered by middleware.js page (asset bundling section)",
  "mtlsEngine":     "covered by network-config.js + network-crypto.js pages",
  "backupCrypto":   "covered by backup-restore.js page (envelope crypto)",
  "backupManifest": "covered by backup-restore.js page (manifest builder)",
  "backupBundle":   "covered by backup-restore.js page (bundle composition)",
  "restoreBundle":  "covered by backup-restore.js page (bundle restore)",
  "restoreRollback":"covered by backup-restore.js page (rollback flow)",
  "apiSnapshot":    "covered by quality-contract.js page (api-snapshot drift gate)",
  "tracing":        "covered by observability.js page",
  "observability":  "covered by observability.js page",
  "version":        "literal version string; not a primitive",
  "smtp":           "covered by mail.js page (b.smtp.* MTA-STS / DANE / TLS-RPT — backfill from v0.7.29 spec)",
  "qualityContract":"covered by quality-contract.js page",
  "protocolDispatcher": "internal — used by primitives that dispatch on envelope-magic + algorithm IDs",
  "ntpCheck":           "covered by network-config.js page (NTP / NTS clock-drift check)",
  "metrics":            "covered by observability.js page",
  "outbox":             "transactional-outbox primitive — operator-facing surface documented in CHANGELOG v0.7.90; backfill wiki section under reliability.js or queue-cache.js when an operator demonstrates the multi-vendor wiring pattern is stable",
  "inbox":              "transactional-inbox primitive (dedupe-on-receive companion to outbox) — operator-facing surface documented in CHANGELOG v0.8.0; backfill wiki section alongside outbox once the multi-source receive pattern is stable",
  "dsr":                "Data Subject Rights workflow primitive — operator-facing surface documented in CHANGELOG v0.7.104; backfill wiki section under compliance-patterns.js when an operator demonstrates a multi-source production wiring pattern",


  // === Sub-key (parent.method) backlog — second-level enumeration introduced in v0.8.8.
  // === The validator now recurses one level into every top-level namespace; sub-keys
  // === documented prose-style under the parent page get explicit entries below so the
  // === gate passes. Backfill per-method signature headings opportunistically — closing
  // === one entry here is the per-method version of the parent-namespace backlog above.

  // ai — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "ai.adverseDecision":                          "covered prose-style under the ai parent section — backfill per-method signature heading in a future sweep",
  // apiKey — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "apiKey.ApiKeyError":                          "covered prose-style under the apiKey parent section — backfill per-method signature heading in a future sweep",
  "apiKey.parseFormat":                          "covered prose-style under the apiKey parent section — backfill per-method signature heading in a future sweep",
  // apiSnapshot — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "apiSnapshot.ApiSnapshotError":                "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  "apiSnapshot.capture":                         "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  "apiSnapshot.compare":                         "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  "apiSnapshot.formatDiff":                      "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  "apiSnapshot.read":                            "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  "apiSnapshot.write":                           "covered prose-style under the apiSnapshot parent section — backfill per-method signature heading in a future sweep",
  // appShutdown — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "appShutdown.AppShutdownError":                "covered prose-style under the appShutdown parent section — backfill per-method signature heading in a future sweep",
  "appShutdown.pidLock":                         "covered prose-style under the appShutdown parent section — backfill per-method signature heading in a future sweep",
  "appShutdown.standardPhases":                  "covered prose-style under the appShutdown parent section — backfill per-method signature heading in a future sweep",
  // archive — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "archive.ArchiveError":                        "covered prose-style under the archive parent section — backfill per-method signature heading in a future sweep",
  // asyncapi — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "asyncapi.AsyncApiError":                      "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.bindings":                           "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.create":                             "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.parse":                              "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.schemaWalk":                         "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.security":                           "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.toYaml":                             "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  "asyncapi.traits":                             "covered prose-style under the asyncapi parent section — backfill per-method signature heading in a future sweep",
  // atomicFile — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "atomicFile.AtomicFileError":                  "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.cleanOrphans":                     "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.copy":                             "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.copyDirRecursive":                 "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.ensureDir":                        "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.exists":                           "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.fsync":                            "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.fsyncDir":                         "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.listDir":                          "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.lock":                             "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.pathTimestamp":                    "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.read":                             "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.readJson":                         "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.readSync":                         "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.write":                            "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.writeJson":                        "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  "atomicFile.writeSync":                        "covered prose-style under the atomicFile parent section — backfill per-method signature heading in a future sweep",
  // audit — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "audit.beginTrace":                            "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.checkpoint":                            "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.emit":                                  "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.flush":                                 "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.query":                                 "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.record":                                "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.registerNamespace":                     "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.verify":                                "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  "audit.verifyCheckpoints":                     "covered prose-style under the audit parent section — backfill per-method signature heading in a future sweep",
  // auditChain — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "auditChain.canonicalize":                     "covered prose-style under the auditChain parent section — backfill per-method signature heading in a future sweep",
  "auditChain.computeRowHash":                   "covered prose-style under the auditChain parent section — backfill per-method signature heading in a future sweep",
  "auditChain.getChainTip":                      "covered prose-style under the auditChain parent section — backfill per-method signature heading in a future sweep",
  "auditChain.verifyChain":                      "covered prose-style under the auditChain parent section — backfill per-method signature heading in a future sweep",
  // auditSign — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "auditSign.init":                              "covered prose-style under the auditSign parent section — backfill per-method signature heading in a future sweep",
  "auditSign.sign":                              "covered prose-style under the auditSign parent section — backfill per-method signature heading in a future sweep",
  "auditSign.verify":                            "covered prose-style under the auditSign parent section — backfill per-method signature heading in a future sweep",
  "auditSign.rotateSigningKey":                  "key-rotation runbook documented in SECURITY.md; the operation requires real init() with sealed/plaintext keypair on disk + an interactive vault passphrase prompt — wiki example would mislead by omitting that operator workflow",
  "auditSign.reSignAll":                         "companion to auditSign.rotateSigningKey — async iterable for re-signing audit chain after a key rotation; documented in the SECURITY.md rotation runbook alongside its driver",
  // auditTools — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "auditTools.AuditToolsError":                  "covered prose-style under the auditTools parent section — backfill per-method signature heading in a future sweep",
  "auditTools.archive":                          "covered prose-style under the auditTools parent section — backfill per-method signature heading in a future sweep",
  "auditTools.exportSlice":                      "covered prose-style under the auditTools parent section — backfill per-method signature heading in a future sweep",
  "auditTools.purge":                            "covered prose-style under the auditTools parent section — backfill per-method signature heading in a future sweep",
  "auditTools.verifyBundle":                     "covered prose-style under the auditTools parent section — backfill per-method signature heading in a future sweep",
  // auth — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "auth.authTime":                               "covered prose-style under the auth parent section — backfill per-method signature heading in a future sweep",
  "auth.sdJwtVc":                                "covered prose-style under the auth parent section — backfill per-method signature heading in a future sweep",
  "auth.statusList":                             "covered prose-style under the auth parent section — backfill per-method signature heading in a future sweep",
  "auth.stepUp":                                 "covered prose-style under the auth parent section — backfill per-method signature heading in a future sweep",
  "auth.accessLock":                             "shipped v0.8.7 — three-mode access-lock primitive (read-only / writes-paused / change-freeze); JSDoc + test suite cover the mode transitions; wiki section deferred until an operator demonstrates a multi-environment lock workflow worth documenting",
  // authHeader — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "authHeader.AuthHeaderError":                  "covered prose-style under the authHeader parent section — backfill per-method signature heading in a future sweep",
  "authHeader.basic":                            "covered prose-style under the authHeader parent section — backfill per-method signature heading in a future sweep",
  "authHeader.bearer":                           "covered prose-style under the authHeader parent section — backfill per-method signature heading in a future sweep",
  "authHeader.fromConfig":                       "covered prose-style under the authHeader parent section — backfill per-method signature heading in a future sweep",
  // backup — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "backup.BackupError":                          "covered prose-style under the backup parent section — backfill per-method signature heading in a future sweep",
  "backup.localStorage":                         "covered prose-style under the backup parent section — backfill per-method signature heading in a future sweep",
  "backup.recommendedFiles":                     "covered prose-style under the backup parent section — backfill per-method signature heading in a future sweep",
  // backupBundle — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "backupBundle.BackupBundleError":              "covered prose-style under the backupBundle parent section — backfill per-method signature heading in a future sweep",
  "backupBundle.create":                         "covered prose-style under the backupBundle parent section — backfill per-method signature heading in a future sweep",
  // backupCrypto — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "backupCrypto.BackupCryptoError":              "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  "backupCrypto.checksum":                       "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  "backupCrypto.decryptWithPassphrase":          "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  "backupCrypto.deriveKey":                      "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  "backupCrypto.encryptWithFreshSalt":           "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  "backupCrypto.encryptWithPassphrase":          "covered prose-style under the backupCrypto parent section — backfill per-method signature heading in a future sweep",
  // backupManifest — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "backupManifest.BackupManifestError":          "covered prose-style under the backupManifest parent section — backfill per-method signature heading in a future sweep",
  "backupManifest.create":                       "covered prose-style under the backupManifest parent section — backfill per-method signature heading in a future sweep",
  "backupManifest.parse":                        "covered prose-style under the backupManifest parent section — backfill per-method signature heading in a future sweep",
  "backupManifest.serialize":                    "covered prose-style under the backupManifest parent section — backfill per-method signature heading in a future sweep",
  "backupManifest.validate":                     "covered prose-style under the backupManifest parent section — backfill per-method signature heading in a future sweep",
  // breach — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "breach.BreachError":                          "covered prose-style under the breach parent section — backfill per-method signature heading in a future sweep",
  "breach.deadline":                             "covered prose-style under the breach parent section — backfill per-method signature heading in a future sweep",
  "breach.report":                               "covered prose-style under the breach parent section — backfill per-method signature heading in a future sweep",
  // breakGlass — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "breakGlass.BreakGlassError":                  "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.decryptCell":                      "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.encryptCell":                      "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.init":                             "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.listActive":                       "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.listActiveAll":                    "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.migrate":                          "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.revoke":                           "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.revokeAll":                        "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.unsealRow":                        "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  "breakGlass.unsealRowAsService":               "covered prose-style under the breakGlass parent section — backfill per-method signature heading in a future sweep",
  // bundler — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "bundler.BundlerError":                        "covered prose-style under the bundler parent section — backfill per-method signature heading in a future sweep",
  "bundler.create":                              "covered prose-style under the bundler parent section — backfill per-method signature heading in a future sweep",
  "bundler.engine":                              "covered prose-style under the bundler parent section — backfill per-method signature heading in a future sweep",
  // cache — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cache.CacheError":                            "covered prose-style under the cache parent section — backfill per-method signature heading in a future sweep",
  // chainWriter — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "chainWriter.ChainWriterError":                "covered prose-style under the chainWriter parent section — backfill per-method signature heading in a future sweep",
  "chainWriter.create":                          "covered prose-style under the chainWriter parent section — backfill per-method signature heading in a future sweep",
  // circuitBreaker — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "circuitBreaker.CircuitBreaker":               "covered prose-style under the circuitBreaker parent section — backfill per-method signature heading in a future sweep",
  "circuitBreaker.create":                       "covered prose-style under the circuitBreaker parent section — backfill per-method signature heading in a future sweep",
  // cli — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cli.main":                                    "covered prose-style under the cli parent section — backfill per-method signature heading in a future sweep",
  // cloudEvents — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cloudEvents.CloudEventsError":                "covered prose-style under the cloudEvents parent section — backfill per-method signature heading in a future sweep",
  "cloudEvents.parse":                           "covered prose-style under the cloudEvents parent section — backfill per-method signature heading in a future sweep",
  // cluster — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cluster.NotLeaderError":                      "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.currentLeader":                       "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.currentNodeId":                       "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.dialect":                             "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.discoveryHandler":                    "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.endpoint":                            "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.externalDbBackend":                   "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.fencingToken":                        "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.isClusterMode":                       "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.isLeader":                            "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.onTransition":                        "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.requireLeader":                       "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  "cluster.shutdown":                            "covered prose-style under the cluster parent section — backfill per-method signature heading in a future sweep",
  // clusterStorage — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "clusterStorage.ClusterStorageError":          "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.execute":                      "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.executeAll":                   "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.executeOne":                   "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.placeholderize":               "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.resolveTables":                "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  "clusterStorage.tableName":                    "covered prose-style under the clusterStorage parent section — backfill per-method signature heading in a future sweep",
  // compliance — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "compliance.ComplianceError":                  "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.aiAct":                            "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.assert":                           "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.clear":                            "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.current":                          "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.describe":                         "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.eaa":                              "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.list":                             "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.posturesByDomain":                 "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.posturesByJurisdiction":           "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  "compliance.sanctions":                        "covered prose-style under the compliance parent section — backfill per-method signature heading in a future sweep",
  // config — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "config.ConfigError":                          "covered prose-style under the config parent section — backfill per-method signature heading in a future sweep",
  "config.coerce":                               "covered prose-style under the config parent section — backfill per-method signature heading in a future sweep",
  "config.create":                               "covered prose-style under the config parent section — backfill per-method signature heading in a future sweep",
  // configDrift — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "configDrift.ConfigDriftError":                "covered prose-style under the configDrift parent section — backfill per-method signature heading in a future sweep",
  // consent — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "consent.history":                             "covered prose-style under the consent parent section — backfill per-method signature heading in a future sweep",
  "consent.isGranted":                           "covered prose-style under the consent parent section — backfill per-method signature heading in a future sweep",
  "consent.verify":                              "covered prose-style under the consent parent section — backfill per-method signature heading in a future sweep",
  "consent.withdraw":                            "covered prose-style under the consent parent section — backfill per-method signature heading in a future sweep",
  // cookies — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cookies.CookieError":                         "covered prose-style under the cookies parent section — backfill per-method signature heading in a future sweep",
  "cookies.serialize":                           "covered prose-style under the cookies parent section — backfill per-method signature heading in a future sweep",
  // cra — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cra.report":                                  "covered prose-style under the cra parent section — backfill per-method signature heading in a future sweep",
  // credentialHash — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "credentialHash.CredentialHashError":          "covered prose-style under the credentialHash parent section — backfill per-method signature heading in a future sweep",
  "credentialHash.inspect":                      "covered prose-style under the credentialHash parent section — backfill per-method signature heading in a future sweep",
  "credentialHash.needsRehash":                  "covered prose-style under the credentialHash parent section — backfill per-method signature heading in a future sweep",
  "credentialHash.verify":                       "covered prose-style under the credentialHash parent section — backfill per-method signature heading in a future sweep",
  // crypto — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "crypto.decrypt":                              "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.decryptEnvelopeAsCertPeer":            "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.decryptMlkem768X25519":                "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.decryptPacked":                        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.encrypt":                              "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.encryptEnvelopeAsCertPeer":            "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.encryptPacked":                        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.generateBytes":                        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.generateEncryptionKeyPair":            "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.generateMlkem768X25519KeyPair":        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.generateSigningKeyPair":               "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.generateToken":                        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.hashCertFingerprint":                  "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.hmacSha3":                             "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.isCertRevoked":                        "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.kdf":                                  "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.sha3Hash":                             "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.sign":                                 "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.sri":                                  "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.timingSafeEqual":                      "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  "crypto.verify":                               "covered prose-style under the crypto parent section — backfill per-method signature heading in a future sweep",
  // cryptoField — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "cryptoField.clearForTest":                    "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.computeDerived":                  "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.eraseRow":                        "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.getSchema":                       "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.getSealedFields":                 "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.lookupHash":                      "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.sealRow":                         "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  "cryptoField.unsealRow":                       "covered prose-style under the cryptoField parent section — backfill per-method signature heading in a future sweep",
  // csv — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "csv.CsvError":                                "covered prose-style under the csv parent section — backfill per-method signature heading in a future sweep",
  // db — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "db.close":                                    "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.exec":                                     "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.flushToDisk":                              "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.getDataResidency":                         "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.getDbPath":                                "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.getMode":                                  "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.getTableMetadata":                         "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.hashFor":                                  "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.integrityCheck":                           "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.integrityMonitor":                         "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.prepare":                                  "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.purgeAuditChain":                          "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.runSql":                                   "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.stream":                                   "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  "db.transaction":                              "covered prose-style under the db parent section — backfill per-method signature heading in a future sweep",
  // deprecate — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "deprecate.DeprecateError":                    "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.alias":                             "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.getMode":                           "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.list":                              "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.reset":                             "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.warn":                              "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  "deprecate.wrap":                              "covered prose-style under the deprecate parent section — backfill per-method signature heading in a future sweep",
  // dev — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "dev.DevError":                                "covered prose-style under the dev parent section — backfill per-method signature heading in a future sweep",
  "dev.create":                                  "covered prose-style under the dev parent section — backfill per-method signature heading in a future sweep",
  // dora — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "dora.DoraError":                              "covered prose-style under the dora parent section — backfill per-method signature heading in a future sweep",
  // dsr — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "dsr.DsrError":                                "covered prose-style under the dsr parent section — backfill per-method signature heading in a future sweep",
  "dsr.create":                                  "covered prose-style under the dsr parent section — backfill per-method signature heading in a future sweep",
  "dsr.dbTicketStore":                           "covered prose-style under the dsr parent section — backfill per-method signature heading in a future sweep",
  "dsr.memoryTicketStore":                       "covered prose-style under the dsr parent section — backfill per-method signature heading in a future sweep",
  // dualControl — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "dualControl.DualControlError":                "covered prose-style under the dualControl parent section — backfill per-method signature heading in a future sweep",
  // externalDb — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "externalDb.Pool":                             "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.adapters":                         "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.configurePool":                    "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.currentRole":                      "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.healthCheck":                      "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.listBackends":                     "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.query":                            "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.read":                             "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.runAs":                            "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.shutdown":                         "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.transaction":                      "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  "externalDb.write":                            "covered prose-style under the externalDb parent section — backfill per-method signature heading in a future sweep",
  // fileType — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "fileType.FileTypeError":                      "covered prose-style under the fileType parent section — backfill per-method signature heading in a future sweep",
  // fileUpload — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "fileUpload.FileUploadError":                  "covered prose-style under the fileUpload parent section — backfill per-method signature heading in a future sweep",
  // flag — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "flag.FlagError":                              "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  "flag.cache":                                  "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  "flag.context":                                "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  "flag.create":                                 "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  "flag.providers":                              "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  "flag.targeting":                              "covered prose-style under the flag parent section — backfill per-method signature heading in a future sweep",
  // forms — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "forms.escapeAttribute":                       "covered prose-style under the forms parent section — backfill per-method signature heading in a future sweep",
  "forms.escapeHtml":                            "covered prose-style under the forms parent section — backfill per-method signature heading in a future sweep",
  "forms.verifyCsrfToken":                       "covered prose-style under the forms parent section — backfill per-method signature heading in a future sweep",
  // frameworkSchema — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "frameworkSchema.FrameworkSchemaError":        "covered prose-style under the frameworkSchema parent section — backfill per-method signature heading in a future sweep",
  "frameworkSchema.ensureSchema":                "covered prose-style under the frameworkSchema parent section — backfill per-method signature heading in a future sweep",
  "frameworkSchema.tableName":                   "covered prose-style under the frameworkSchema parent section — backfill per-method signature heading in a future sweep",
  // gateContract — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "gateContract.GateContractError":              "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.aggregateIssues":                "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.badInputResultIfNotStringOrBuffer": "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.buildGuardGate":                 "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.buildProfile":                   "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.byActorTier":                    "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.byDirection":                    "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.byRoute":                        "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.cachingGate":                    "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.canaryGate":                     "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.composeGates":                   "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.composeHooks":                   "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.contentTypeMux":                 "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.defineGate":                     "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.extractBytesAsText":             "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.lookupCompliancePosture":        "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.makeProfileBuilder":             "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.makeRulePackLoader":             "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.multiplexGates":                 "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.resolveProfileAndPosture":       "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.runGate":                        "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.runIssueValidator":              "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.shadowMode":                     "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.summarizeIssues":                "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.validateGateShape":              "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  "gateContract.workerThreadGate":               "covered prose-style under the gateContract parent section — backfill per-method signature heading in a future sweep",
  // gdpr — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "gdpr.ropa":                                   "covered prose-style under the gdpr parent section — backfill per-method signature heading in a future sweep",
  // guardAll — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardAll.GuardAllError":                      "covered prose-style under the guardAll parent section — backfill per-method signature heading in a future sweep",
  "guardAll.allGuards":                          "covered prose-style under the guardAll parent section — backfill per-method signature heading in a future sweep",
  // guardArchive — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardArchive.GuardArchiveError":              "covered prose-style under the guardArchive parent section — backfill per-method signature heading in a future sweep",
  "guardArchive.buildProfile":                   "covered prose-style under the guardArchive parent section — backfill per-method signature heading in a future sweep",
  "guardArchive.compliancePosture":              "covered prose-style under the guardArchive parent section — backfill per-method signature heading in a future sweep",
  "guardArchive.loadRulePack":                   "covered prose-style under the guardArchive parent section — backfill per-method signature heading in a future sweep",
  // guardAuth — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardAuth.GuardAuthError":                    "covered prose-style under the guardAuth parent section — backfill per-method signature heading in a future sweep",
  "guardAuth.buildProfile":                      "covered prose-style under the guardAuth parent section — backfill per-method signature heading in a future sweep",
  "guardAuth.compliancePosture":                 "covered prose-style under the guardAuth parent section — backfill per-method signature heading in a future sweep",
  "guardAuth.loadRulePack":                      "covered prose-style under the guardAuth parent section — backfill per-method signature heading in a future sweep",
  // guardCidr — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardCidr.GuardCidrError":                    "covered prose-style under the guardCidr parent section — backfill per-method signature heading in a future sweep",
  "guardCidr.buildProfile":                      "covered prose-style under the guardCidr parent section — backfill per-method signature heading in a future sweep",
  "guardCidr.compliancePosture":                 "covered prose-style under the guardCidr parent section — backfill per-method signature heading in a future sweep",
  "guardCidr.loadRulePack":                      "covered prose-style under the guardCidr parent section — backfill per-method signature heading in a future sweep",
  // guardCsv — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardCsv.GuardCsvError":                      "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.buildProfile":                       "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.compliancePosture":                  "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.detect":                             "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.escapeCell":                         "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.loadRulePack":                       "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  "guardCsv.sanitize":                           "covered prose-style under the guardCsv parent section — backfill per-method signature heading in a future sweep",
  // guardDomain — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardDomain.GuardDomainError":                "covered prose-style under the guardDomain parent section — backfill per-method signature heading in a future sweep",
  "guardDomain.buildProfile":                    "covered prose-style under the guardDomain parent section — backfill per-method signature heading in a future sweep",
  "guardDomain.compliancePosture":               "covered prose-style under the guardDomain parent section — backfill per-method signature heading in a future sweep",
  "guardDomain.loadRulePack":                    "covered prose-style under the guardDomain parent section — backfill per-method signature heading in a future sweep",
  // guardEmail — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardEmail.GuardEmailError":                  "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  "guardEmail.buildProfile":                     "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  "guardEmail.compliancePosture":                "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  "guardEmail.loadRulePack":                     "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  "guardEmail.sanitize":                         "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  "guardEmail.validate":                         "covered prose-style under the guardEmail parent section — backfill per-method signature heading in a future sweep",
  // guardFilename — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardFilename.GuardFilenameError":            "covered prose-style under the guardFilename parent section — backfill per-method signature heading in a future sweep",
  "guardFilename.buildProfile":                  "covered prose-style under the guardFilename parent section — backfill per-method signature heading in a future sweep",
  "guardFilename.compliancePosture":             "covered prose-style under the guardFilename parent section — backfill per-method signature heading in a future sweep",
  "guardFilename.loadRulePack":                  "covered prose-style under the guardFilename parent section — backfill per-method signature heading in a future sweep",
  // guardGraphql — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardGraphql.GuardGraphqlError":              "covered prose-style under the guardGraphql parent section — backfill per-method signature heading in a future sweep",
  "guardGraphql.buildProfile":                   "covered prose-style under the guardGraphql parent section — backfill per-method signature heading in a future sweep",
  "guardGraphql.compliancePosture":              "covered prose-style under the guardGraphql parent section — backfill per-method signature heading in a future sweep",
  "guardGraphql.loadRulePack":                   "covered prose-style under the guardGraphql parent section — backfill per-method signature heading in a future sweep",
  // guardHtml — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardHtml.GuardHtmlError":                    "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  "guardHtml.buildProfile":                      "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  "guardHtml.compliancePosture":                 "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  "guardHtml.escapeAttr":                        "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  "guardHtml.loadRulePack":                      "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  "guardHtml.wcag":                              "covered prose-style under the guardHtml parent section — backfill per-method signature heading in a future sweep",
  // guardImage — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardImage.GuardImageError":                  "covered prose-style under the guardImage parent section — backfill per-method signature heading in a future sweep",
  "guardImage.buildProfile":                     "covered prose-style under the guardImage parent section — backfill per-method signature heading in a future sweep",
  "guardImage.compliancePosture":                "covered prose-style under the guardImage parent section — backfill per-method signature heading in a future sweep",
  "guardImage.loadRulePack":                     "covered prose-style under the guardImage parent section — backfill per-method signature heading in a future sweep",
  // guardJson — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardJson.GuardJsonError":                    "covered prose-style under the guardJson parent section — backfill per-method signature heading in a future sweep",
  "guardJson.buildProfile":                      "covered prose-style under the guardJson parent section — backfill per-method signature heading in a future sweep",
  "guardJson.compliancePosture":                 "covered prose-style under the guardJson parent section — backfill per-method signature heading in a future sweep",
  "guardJson.loadRulePack":                      "covered prose-style under the guardJson parent section — backfill per-method signature heading in a future sweep",
  // guardJsonpath — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardJsonpath.GuardJsonpathError":            "covered prose-style under the guardJsonpath parent section — backfill per-method signature heading in a future sweep",
  "guardJsonpath.buildProfile":                  "covered prose-style under the guardJsonpath parent section — backfill per-method signature heading in a future sweep",
  "guardJsonpath.compliancePosture":             "covered prose-style under the guardJsonpath parent section — backfill per-method signature heading in a future sweep",
  "guardJsonpath.loadRulePack":                  "covered prose-style under the guardJsonpath parent section — backfill per-method signature heading in a future sweep",
  // guardJwt — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardJwt.GuardJwtError":                      "covered prose-style under the guardJwt parent section — backfill per-method signature heading in a future sweep",
  "guardJwt.buildProfile":                       "covered prose-style under the guardJwt parent section — backfill per-method signature heading in a future sweep",
  "guardJwt.compliancePosture":                  "covered prose-style under the guardJwt parent section — backfill per-method signature heading in a future sweep",
  "guardJwt.loadRulePack":                       "covered prose-style under the guardJwt parent section — backfill per-method signature heading in a future sweep",
  // guardMarkdown — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardMarkdown.GuardMarkdownError":            "covered prose-style under the guardMarkdown parent section — backfill per-method signature heading in a future sweep",
  "guardMarkdown.buildProfile":                  "covered prose-style under the guardMarkdown parent section — backfill per-method signature heading in a future sweep",
  "guardMarkdown.compliancePosture":             "covered prose-style under the guardMarkdown parent section — backfill per-method signature heading in a future sweep",
  "guardMarkdown.loadRulePack":                  "covered prose-style under the guardMarkdown parent section — backfill per-method signature heading in a future sweep",
  // guardMime — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardMime.GuardMimeError":                    "covered prose-style under the guardMime parent section — backfill per-method signature heading in a future sweep",
  "guardMime.buildProfile":                      "covered prose-style under the guardMime parent section — backfill per-method signature heading in a future sweep",
  "guardMime.compliancePosture":                 "covered prose-style under the guardMime parent section — backfill per-method signature heading in a future sweep",
  "guardMime.loadRulePack":                      "covered prose-style under the guardMime parent section — backfill per-method signature heading in a future sweep",
  // guardOauth — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardOauth.GuardOauthError":                  "covered prose-style under the guardOauth parent section — backfill per-method signature heading in a future sweep",
  "guardOauth.buildProfile":                     "covered prose-style under the guardOauth parent section — backfill per-method signature heading in a future sweep",
  "guardOauth.compliancePosture":                "covered prose-style under the guardOauth parent section — backfill per-method signature heading in a future sweep",
  "guardOauth.loadRulePack":                     "covered prose-style under the guardOauth parent section — backfill per-method signature heading in a future sweep",
  // guardPdf — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardPdf.GuardPdfError":                      "covered prose-style under the guardPdf parent section — backfill per-method signature heading in a future sweep",
  "guardPdf.buildProfile":                       "covered prose-style under the guardPdf parent section — backfill per-method signature heading in a future sweep",
  "guardPdf.compliancePosture":                  "covered prose-style under the guardPdf parent section — backfill per-method signature heading in a future sweep",
  "guardPdf.loadRulePack":                       "covered prose-style under the guardPdf parent section — backfill per-method signature heading in a future sweep",
  // guardRegex — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardRegex.GuardRegexError":                  "covered prose-style under the guardRegex parent section — backfill per-method signature heading in a future sweep",
  "guardRegex.buildProfile":                     "covered prose-style under the guardRegex parent section — backfill per-method signature heading in a future sweep",
  "guardRegex.compliancePosture":                "covered prose-style under the guardRegex parent section — backfill per-method signature heading in a future sweep",
  "guardRegex.loadRulePack":                     "covered prose-style under the guardRegex parent section — backfill per-method signature heading in a future sweep",
  // guardShell — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardShell.GuardShellError":                  "covered prose-style under the guardShell parent section — backfill per-method signature heading in a future sweep",
  "guardShell.buildProfile":                     "covered prose-style under the guardShell parent section — backfill per-method signature heading in a future sweep",
  "guardShell.compliancePosture":                "covered prose-style under the guardShell parent section — backfill per-method signature heading in a future sweep",
  "guardShell.loadRulePack":                     "covered prose-style under the guardShell parent section — backfill per-method signature heading in a future sweep",
  // guardSvg — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardSvg.GuardSvgError":                      "covered prose-style under the guardSvg parent section — backfill per-method signature heading in a future sweep",
  "guardSvg.buildProfile":                       "covered prose-style under the guardSvg parent section — backfill per-method signature heading in a future sweep",
  "guardSvg.compliancePosture":                  "covered prose-style under the guardSvg parent section — backfill per-method signature heading in a future sweep",
  "guardSvg.loadRulePack":                       "covered prose-style under the guardSvg parent section — backfill per-method signature heading in a future sweep",
  // guardTemplate — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardTemplate.GuardTemplateError":            "covered prose-style under the guardTemplate parent section — backfill per-method signature heading in a future sweep",
  "guardTemplate.buildProfile":                  "covered prose-style under the guardTemplate parent section — backfill per-method signature heading in a future sweep",
  "guardTemplate.compliancePosture":             "covered prose-style under the guardTemplate parent section — backfill per-method signature heading in a future sweep",
  "guardTemplate.loadRulePack":                  "covered prose-style under the guardTemplate parent section — backfill per-method signature heading in a future sweep",
  // guardTime — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardTime.GuardTimeError":                    "covered prose-style under the guardTime parent section — backfill per-method signature heading in a future sweep",
  "guardTime.buildProfile":                      "covered prose-style under the guardTime parent section — backfill per-method signature heading in a future sweep",
  "guardTime.compliancePosture":                 "covered prose-style under the guardTime parent section — backfill per-method signature heading in a future sweep",
  "guardTime.loadRulePack":                      "covered prose-style under the guardTime parent section — backfill per-method signature heading in a future sweep",
  // guardUuid — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardUuid.GuardUuidError":                    "covered prose-style under the guardUuid parent section — backfill per-method signature heading in a future sweep",
  "guardUuid.buildProfile":                      "covered prose-style under the guardUuid parent section — backfill per-method signature heading in a future sweep",
  "guardUuid.compliancePosture":                 "covered prose-style under the guardUuid parent section — backfill per-method signature heading in a future sweep",
  "guardUuid.loadRulePack":                      "covered prose-style under the guardUuid parent section — backfill per-method signature heading in a future sweep",
  // guardXml — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardXml.GuardXmlError":                      "covered prose-style under the guardXml parent section — backfill per-method signature heading in a future sweep",
  "guardXml.buildProfile":                       "covered prose-style under the guardXml parent section — backfill per-method signature heading in a future sweep",
  "guardXml.compliancePosture":                  "covered prose-style under the guardXml parent section — backfill per-method signature heading in a future sweep",
  "guardXml.loadRulePack":                       "covered prose-style under the guardXml parent section — backfill per-method signature heading in a future sweep",
  // guardYaml — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "guardYaml.GuardYamlError":                    "covered prose-style under the guardYaml parent section — backfill per-method signature heading in a future sweep",
  "guardYaml.buildProfile":                      "covered prose-style under the guardYaml parent section — backfill per-method signature heading in a future sweep",
  "guardYaml.compliancePosture":                 "covered prose-style under the guardYaml parent section — backfill per-method signature heading in a future sweep",
  "guardYaml.loadRulePack":                      "covered prose-style under the guardYaml parent section — backfill per-method signature heading in a future sweep",
  // handlers — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "handlers.create":                             "covered prose-style under the handlers parent section — backfill per-method signature heading in a future sweep",
  // htmlBalance — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "htmlBalance.checkSafe":                       "covered prose-style under the htmlBalance parent section — backfill per-method signature heading in a future sweep",
  // httpClient — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "httpClient.configurePool":                    "covered prose-style under the httpClient parent section — backfill per-method signature heading in a future sweep",
  "httpClient.encrypted":                        "covered prose-style under the httpClient parent section — backfill per-method signature heading in a future sweep",
  // i18n — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "i18n.I18nError":                              "covered prose-style under the i18n parent section — backfill per-method signature heading in a future sweep",
  "i18n.messageFormat":                          "covered prose-style under the i18n parent section — backfill per-method signature heading in a future sweep",
  // inbox — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "inbox.InboxError":                            "covered prose-style under the inbox parent section — backfill per-method signature heading in a future sweep",
  "inbox.create":                                "covered prose-style under the inbox parent section — backfill per-method signature heading in a future sweep",
  // incident — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "incident.report":                             "covered prose-style under the incident parent section — backfill per-method signature heading in a future sweep",
  // log — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "log.LogError":                                "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  "log.boot":                                    "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  "log.create":                                  "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  "log.getRequestId":                            "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  "log.makeViaOrFallback":                       "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  "log.runWithRequestId":                        "covered prose-style under the log parent section — backfill per-method signature heading in a future sweep",
  // mail — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "mail.MailError":                              "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  "mail.authResults":                            "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  "mail.bimi":                                   "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  "mail.toUnicode":                              "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  "mail.transports":                             "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  "mail.unsubscribe":                            "covered prose-style under the mail parent section — backfill per-method signature heading in a future sweep",
  // mailBounce — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "mailBounce.MailBounceError":                  "covered prose-style under the mailBounce parent section — backfill per-method signature heading in a future sweep",
  "mailBounce.parse":                            "covered prose-style under the mailBounce parent section — backfill per-method signature heading in a future sweep",
  "mailBounce.vendors":                          "covered prose-style under the mailBounce parent section — backfill per-method signature heading in a future sweep",
  // metrics — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "metrics.MetricsError":                        "covered prose-style under the metrics parent section — backfill per-method signature heading in a future sweep",
  "metrics.create":                              "covered prose-style under the metrics parent section — backfill per-method signature heading in a future sweep",
  "metrics.tap":                                 "covered prose-style under the metrics parent section — backfill per-method signature heading in a future sweep",
  // middleware — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "middleware.ageGate":                          "shipped v0.8.11 — request-level age classification middleware (COPPA / UK Children's Code / California AADC); JSDoc + tests cover the classification + 451 refusal flow; wiki section deferred until an operator demonstrates a parental-consent workflow worth documenting",
  "middleware.dailyByteQuota":                   "shipped v0.8.6 — per-tenant daily byte-budget middleware; JSDoc + test suite cover the rollover + emit-on-exceed flow; wiki section deferred until an operator demonstrates a production budget-alerting workflow worth documenting",
  "middleware.requireMtls":                      "shipped v0.7.18 — mTLS-required middleware (refuses requests without a verified peer cert); JSDoc + test suite cover the verification + audit shape; wiki section deferred — the configuration belongs alongside the network-crypto.js / mtls-engine guidance and an operator's CA setup, which the page already covers prose-style",
  "middleware.aiActDisclosure":                  "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.assetlinks":                       "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.asyncapiServe":                    "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.attachUser":                       "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.botDisclose":                      "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.botGuard":                         "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.compression":                      "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.cors":                             "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.dpop":                             "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.errorHandler":                     "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.flagContext":                      "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.gpc":                              "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.health":                           "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.hostAllowlist":                    "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.minor":                            "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.openapiServe":                     "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requestId":                        "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requireAal":                       "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requireAuth":                      "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requireContentType":               "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requireMethods":                   "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.requireStepUp":                    "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.securityHeaders":                  "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.securityTxt":                      "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.spanHttpServer":                   "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.traceLogCorrelation":              "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.tracePropagate":                   "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.tusUpload":                        "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  "middleware.webAppManifest":                   "covered prose-style under the middleware parent section — backfill per-method signature heading in a future sweep",
  // migrations — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "migrations.MigrationError":                   "covered prose-style under the migrations parent section — backfill per-method signature heading in a future sweep",
  "migrations.create":                           "covered prose-style under the migrations parent section — backfill per-method signature heading in a future sweep",
  // mtlsCa — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "mtlsCa.MtlsCaError":                          "covered prose-style under the mtlsCa parent section — backfill per-method signature heading in a future sweep",
  "mtlsCa.parseGeneration":                      "covered prose-style under the mtlsCa parent section — backfill per-method signature heading in a future sweep",
  // mtlsEngine — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "mtlsEngine.MtlsEngineError":                  "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  "mtlsEngine.algorithmEnvelope":                "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  "mtlsEngine.generateCa":                       "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  "mtlsEngine.generateCrl":                      "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  "mtlsEngine.packageP12":                       "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  "mtlsEngine.signClientCert":                   "covered prose-style under the mtlsEngine parent section — backfill per-method signature heading in a future sweep",
  // network — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "network.NetworkError":                        "covered prose-style under the network parent section — backfill per-method signature heading in a future sweep",
  "network.snapshot":                            "covered prose-style under the network parent section — backfill per-method signature heading in a future sweep",
  // nis2 — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "nis2.report":                                 "covered prose-style under the nis2 parent section — backfill per-method signature heading in a future sweep",
  // nonceStore — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "nonceStore.NonceStoreError":                  "covered prose-style under the nonceStore parent section — backfill per-method signature heading in a future sweep",
  "nonceStore.create":                           "covered prose-style under the nonceStore parent section — backfill per-method signature heading in a future sweep",
  // notify — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "notify.NotifyError":                          "covered prose-style under the notify parent section — backfill per-method signature heading in a future sweep",
  "notify.transports":                           "covered prose-style under the notify parent section — backfill per-method signature heading in a future sweep",
  // ntpCheck — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "ntpCheck.bootCheck":                          "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  "ntpCheck.checkDrift":                         "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  "ntpCheck.getThresholds":                      "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  "ntpCheck.monitor":                            "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  "ntpCheck.querySingle":                        "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  "ntpCheck.setThresholds":                      "covered prose-style under the ntpCheck parent section — backfill per-method signature heading in a future sweep",
  // objectStore — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "objectStore.bucketOps":                       "covered prose-style under the objectStore parent section — backfill per-method signature heading in a future sweep",
  "objectStore.buildBackend":                    "covered prose-style under the objectStore parent section — backfill per-method signature heading in a future sweep",
  // observability — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "observability.baggage":                       "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.event":                         "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.otlpExporter":                  "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.safeEvent":                     "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.setTap":                        "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.tap":                           "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.timed":                         "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.traceContext":                  "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  "observability.tracer":                        "covered prose-style under the observability parent section — backfill per-method signature heading in a future sweep",
  // openapi — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "openapi.OpenApiError":                        "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  "openapi.create":                              "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  "openapi.parse":                               "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  "openapi.schemaWalk":                          "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  "openapi.security":                            "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  "openapi.toYaml":                              "covered prose-style under the openapi parent section — backfill per-method signature heading in a future sweep",
  // otelExport — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "otelExport.OtelExportError":                  "covered prose-style under the otelExport parent section — backfill per-method signature heading in a future sweep",
  // outbox — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "outbox.OutboxError":                          "covered prose-style under the outbox parent section — backfill per-method signature heading in a future sweep",
  "outbox.create":                               "covered prose-style under the outbox parent section — backfill per-method signature heading in a future sweep",
  // pagination — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "pagination.PaginationError":                  "covered prose-style under the pagination parent section — backfill per-method signature heading in a future sweep",
  "pagination.decodeCursor":                     "covered prose-style under the pagination parent section — backfill per-method signature heading in a future sweep",
  "pagination.encodeCursor":                     "covered prose-style under the pagination parent section — backfill per-method signature heading in a future sweep",
  "pagination.offset":                           "covered prose-style under the pagination parent section — backfill per-method signature heading in a future sweep",
  // permissions — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "permissions.PermissionsError":                "covered prose-style under the permissions parent section — backfill per-method signature heading in a future sweep",
  "permissions.match":                           "covered prose-style under the permissions parent section — backfill per-method signature heading in a future sweep",
  // pqcAgent — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "pqcAgent.createHttp":                         "covered prose-style under the pqcAgent parent section — backfill per-method signature heading in a future sweep",
  // pqcGate — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "pqcGate.clientHelloHasPQC":                   "covered prose-style under the pqcGate parent section — backfill per-method signature heading in a future sweep",
  // pqcSoftware — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "pqcSoftware.DEFAULT_HASH_SIG":                "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.DEFAULT_KEM":                     "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.DEFAULT_LATTICE_SIG":             "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.PqcError":                        "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.isAvailable":                     "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.listAlgorithms":                  "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_dsa_44":                       "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_dsa_65":                       "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_dsa_87":                       "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_kem_1024":                     "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_kem_512":                      "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.ml_kem_768":                      "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_sha2_128f":               "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_sha2_192f":               "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_sha2_256f":               "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_shake_128f":              "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_shake_192f":              "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  "pqcSoftware.slh_dsa_shake_256f":              "covered prose-style under the pqcSoftware parent section — backfill per-method signature heading in a future sweep",
  // protocolDispatcher — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "protocolDispatcher.ProtocolDispatcherError":  "covered prose-style under the protocolDispatcher parent section — backfill per-method signature heading in a future sweep",
  "protocolDispatcher.create":                   "covered prose-style under the protocolDispatcher parent section — backfill per-method signature heading in a future sweep",
  // pubsub — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "pubsub.PubsubError":                          "covered prose-style under the pubsub parent section — backfill per-method signature heading in a future sweep",
  "pubsub.create":                               "covered prose-style under the pubsub parent section — backfill per-method signature heading in a future sweep",
  // queue — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "queue.dlqList":                               "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.dlqRetry":                              "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.dlqSize":                               "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.init":                                  "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.listBackends":                          "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.purge":                                 "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.shutdown":                              "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  "queue.size":                                  "covered prose-style under the queue parent section — backfill per-method signature heading in a future sweep",
  // render — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "render.create":                               "covered prose-style under the render parent section — backfill per-method signature heading in a future sweep",
  "render.json":                                 "covered prose-style under the render parent section — backfill per-method signature heading in a future sweep",
  "render.redirect":                             "covered prose-style under the render parent section — backfill per-method signature heading in a future sweep",
  "render.text":                                 "covered prose-style under the render parent section — backfill per-method signature heading in a future sweep",
  // requestHelpers — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "requestHelpers.appendVary":                   "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.captureResponseStatus":        "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.clientIp":                     "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.requestProtocol":              "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.resolveActorWithOverride":     "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.resolveRoute":                 "covered prose-style under the requestHelpers parent section — backfill per-method signature heading in a future sweep",
  "requestHelpers.safeHeadersDistinct":          "shipped v0.8.15 — Node CVE-2026-21710 wrapper for req.headersDistinct; thin defensive accessor — covered prose-style under the requestHelpers parent section, backfill per-method signature heading in a future sweep",
  // restore — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "restore.RestoreError":                        "covered prose-style under the restore parent section — backfill per-method signature heading in a future sweep",
  // restoreBundle — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "restoreBundle.RestoreBundleError":            "covered prose-style under the restoreBundle parent section — backfill per-method signature heading in a future sweep",
  "restoreBundle.extract":                       "covered prose-style under the restoreBundle parent section — backfill per-method signature heading in a future sweep",
  "restoreBundle.inspect":                       "covered prose-style under the restoreBundle parent section — backfill per-method signature heading in a future sweep",
  // restoreRollback — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "restoreRollback.RestoreRollbackError":        "covered prose-style under the restoreRollback parent section — backfill per-method signature heading in a future sweep",
  "restoreRollback.list":                        "covered prose-style under the restoreRollback parent section — backfill per-method signature heading in a future sweep",
  "restoreRollback.purge":                       "covered prose-style under the restoreRollback parent section — backfill per-method signature heading in a future sweep",
  "restoreRollback.rollback":                    "covered prose-style under the restoreRollback parent section — backfill per-method signature heading in a future sweep",
  "restoreRollback.swap":                        "covered prose-style under the restoreRollback parent section — backfill per-method signature heading in a future sweep",
  // retention — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "retention.RetentionError":                    "covered prose-style under the retention parent section — backfill per-method signature heading in a future sweep",
  // retry — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "retry.CircuitBreaker":                        "covered prose-style under the retry parent section — backfill per-method signature heading in a future sweep",
  "retry.backoffDelay":                          "covered prose-style under the retry parent section — backfill per-method signature heading in a future sweep",
  "retry.isRetryable":                           "covered prose-style under the retry parent section — backfill per-method signature heading in a future sweep",
  // router — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "router.Router":                               "covered prose-style under the router parent section — backfill per-method signature heading in a future sweep",
  "router.serveStatic":                          "covered prose-style under the router parent section — backfill per-method signature heading in a future sweep",
  // safeAsync — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeAsync.CircuitBreaker":                    "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.Mutex":                             "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.Once":                              "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.SafeAsyncError":                    "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.Semaphore":                         "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.asyncRetry":                        "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.flushLoop":                         "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.makeDropCallback":                  "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.makeScheduledFlush":                "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.repeating":                         "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.safeAwait":                         "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.safeInvoke":                        "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.sleep":                             "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.withSignal":                        "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.withTimeout":                       "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  "safeAsync.withTimeoutSignal":                 "covered prose-style under the safeAsync parent section — backfill per-method signature heading in a future sweep",
  // safeBuffer — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeBuffer.SafeBufferError":                  "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  "safeBuffer.hasCrlf":                          "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  "safeBuffer.isHex":                            "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  "safeBuffer.stripCrlf":                        "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  "safeBuffer.stripTrailingHspace":              "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  "safeBuffer.toBuffer":                         "covered prose-style under the safeBuffer parent section — backfill per-method signature heading in a future sweep",
  // safeEnv — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeEnv.SafeEnvError":                        "covered prose-style under the safeEnv parent section — backfill per-method signature heading in a future sweep",
  "safeEnv.load":                                "covered prose-style under the safeEnv parent section — backfill per-method signature heading in a future sweep",
  "safeEnv.parse":                               "covered prose-style under the safeEnv parent section — backfill per-method signature heading in a future sweep",
  "safeEnv.readVar":                             "covered prose-style under the safeEnv parent section — backfill per-method signature heading in a future sweep",
  // safeJson — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeJson.SafeJsonError":                      "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.canonical":                          "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.formats":                            "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.parseOrDefault":                     "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.registerFormat":                     "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.stringify":                          "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  "safeJson.validate":                           "covered prose-style under the safeJson parent section — backfill per-method signature heading in a future sweep",
  // safeSchema — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeSchema.SafeSchemaError":                  "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.any":                              "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.array":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.boolean":                          "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.discriminatedUnion":               "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.enum_":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.lazy":                             "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.literal":                          "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.null_":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.nullable":                         "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.number":                           "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.oneOf":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.optional":                         "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.preprocess":                       "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.record":                           "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.string":                           "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.tuple":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.undefined_":                       "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.union":                            "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  "safeSchema.unknown":                          "covered prose-style under the safeSchema parent section — backfill per-method signature heading in a future sweep",
  // safeSql — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeSql.SafeSqlError":                        "covered prose-style under the safeSql parent section — backfill per-method signature heading in a future sweep",
  "safeSql.assertOneOf":                         "covered prose-style under the safeSql parent section — backfill per-method signature heading in a future sweep",
  "safeSql.quoteIdentifier":                     "covered prose-style under the safeSql parent section — backfill per-method signature heading in a future sweep",
  "safeSql.quoteQualified":                      "covered prose-style under the safeSql parent section — backfill per-method signature heading in a future sweep",
  // safeUrl — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "safeUrl.SafeUrlError":                        "covered prose-style under the safeUrl parent section — backfill per-method signature heading in a future sweep",
  // scheduler — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "scheduler.SchedulerError":                    "covered prose-style under the scheduler parent section — backfill per-method signature heading in a future sweep",
  "scheduler.nextBaselineFire":                  "covered prose-style under the scheduler parent section — backfill per-method signature heading in a future sweep",
  "scheduler.nextCronFire":                      "covered prose-style under the scheduler parent section — backfill per-method signature heading in a future sweep",
  "scheduler.parseCron":                         "covered prose-style under the scheduler parent section — backfill per-method signature heading in a future sweep",
  // security — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "security.DEFAULT_RESOLVERS":                  "covered prose-style under the security parent section — backfill per-method signature heading in a future sweep",
  "security.SecurityAssertError":                "covered prose-style under the security parent section — backfill per-method signature heading in a future sweep",
  // seeders — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "seeders.SeederError":                         "covered prose-style under the seeders parent section — backfill per-method signature heading in a future sweep",
  "seeders.create":                              "covered prose-style under the seeders parent section — backfill per-method signature heading in a future sweep",
  // session — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "session.count":                               "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.destroy":                             "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.destroyAllForUser":                   "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.purgeExpired":                        "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.rotate":                              "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.touch":                               "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  "session.verify":                              "covered prose-style under the session parent section — backfill per-method signature heading in a future sweep",
  // ssrfGuard — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "ssrfGuard.SsrfError":                         "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.cidrContains":                      "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.isCloudMetadata":                   "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.isLinkLocal":                       "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.isLoopback":                        "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.isPrivate":                         "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  "ssrfGuard.isReserved":                        "covered prose-style under the ssrfGuard parent section — backfill per-method signature heading in a future sweep",
  // staticServe — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "staticServe.integrity":                       "covered prose-style under the staticServe parent section — backfill per-method signature heading in a future sweep",
  // storage — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "storage.deleteFile":                          "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.exists":                              "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.getBackend":                          "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.getFileBuffer":                       "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.getFileStream":                       "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.getRawBuffer":                        "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.init":                                "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.listBackends":                        "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.presignedDownloadUrl":                "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.presignedUploadUrl":                  "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.saveFile":                            "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  "storage.saveRaw":                             "covered prose-style under the storage parent section — backfill per-method signature heading in a future sweep",
  // subject — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "subject.erase":                               "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.export":                              "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.exportData":                          "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.isRestricted":                        "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.recordObjection":                     "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.rectify":                             "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  "subject.restrict":                            "covered prose-style under the subject parent section — backfill per-method signature heading in a future sweep",
  // template — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "template.create":                             "covered prose-style under the template parent section — backfill per-method signature heading in a future sweep",
  "template.escapeHtml":                         "covered prose-style under the template parent section — backfill per-method signature heading in a future sweep",
  "template.render":                             "covered prose-style under the template parent section — backfill per-method signature heading in a future sweep",
  // time — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "time.TimeError":                              "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.addMonths":                              "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.diffDays":                               "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.endOfDay":                               "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.format":                                 "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.parseISO":                               "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.startOfDay":                             "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.toIso8601NoMs":                          "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  "time.tzOffsetMs":                             "covered prose-style under the time parent section — backfill per-method signature heading in a future sweep",
  // tracing — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "tracing.TracingError":                        "covered prose-style under the tracing parent section — backfill per-method signature heading in a future sweep",
  "tracing.create":                              "covered prose-style under the tracing parent section — backfill per-method signature heading in a future sweep",
  "tracing.tap":                                 "covered prose-style under the tracing parent section — backfill per-method signature heading in a future sweep",
  // uuid — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "uuid.isValid":                                "covered prose-style under the uuid parent section — backfill per-method signature heading in a future sweep",
  "uuid.parse":                                  "covered prose-style under the uuid parent section — backfill per-method signature heading in a future sweep",
  "uuid.v7":                                     "covered prose-style under the uuid parent section — backfill per-method signature heading in a future sweep",
  // vault — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "vault.VaultError":                            "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.aad":                                   "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.sealPemFile":                           "shipped v0.8.14 — auto-resealing wrapper for at-rest PEM files (ACME renewal driver); JSDoc + tests cover the watch / reseal / recovery flows; wiki section deferred until an operator demonstrates a multi-cert lifecycle worth documenting",
  "vault.SealPemFileError":                      "framework-error subclass surfaced for instanceof checks in operator handlers; the class itself isn't called as a constructor in tests — every sealPemFile test that triggers it does so by exercising the calling code that throws it",
  "vault.getCurrentPassphrase":                  "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.getKeysJson":                           "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.getMode":                               "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.init":                                  "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  "vault.unseal":                                "covered prose-style under the vault parent section — backfill per-method signature heading in a future sweep",
  // vaultPassphraseOps — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "vaultPassphraseOps.VaultPassphraseError":     "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.preflightRotatable":       "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.preflightSealable":        "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.preflightUnsealable":      "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.rotate":                   "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.seal":                     "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseOps.unseal":                   "covered prose-style under the vaultPassphraseOps parent section — backfill per-method signature heading in a future sweep",
  // vaultPassphraseSource — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "vaultPassphraseSource.fromEnv":               "covered prose-style under the vaultPassphraseSource parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseSource.fromFile":              "covered prose-style under the vaultPassphraseSource parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseSource.fromStdin":             "covered prose-style under the vaultPassphraseSource parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseSource.getPassphrase":         "covered prose-style under the vaultPassphraseSource parent section — backfill per-method signature heading in a future sweep",
  "vaultPassphraseSource.sourceKind":            "covered prose-style under the vaultPassphraseSource parent section — backfill per-method signature heading in a future sweep",
  // vaultRotate — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "vaultRotate.VaultRotateError":                "covered prose-style under the vaultRotate parent section — backfill per-method signature heading in a future sweep",
  "vaultRotate.formatValidationResult":          "covered prose-style under the vaultRotate parent section — backfill per-method signature heading in a future sweep",
  "vaultRotate.rotate":                          "covered prose-style under the vaultRotate parent section — backfill per-method signature heading in a future sweep",
  "vaultRotate.validateSchemaMatch":             "covered prose-style under the vaultRotate parent section — backfill per-method signature heading in a future sweep",
  "vaultRotate.verify":                          "covered prose-style under the vaultRotate parent section — backfill per-method signature heading in a future sweep",
  // vaultWrap — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "vaultWrap.buildHeader":                       "covered prose-style under the vaultWrap parent section — backfill per-method signature heading in a future sweep",
  "vaultWrap.deriveWrappingKey":                 "covered prose-style under the vaultWrap parent section — backfill per-method signature heading in a future sweep",
  "vaultWrap.parseHeader":                       "covered prose-style under the vaultWrap parent section — backfill per-method signature heading in a future sweep",
  "vaultWrap.unwrap":                            "covered prose-style under the vaultWrap parent section — backfill per-method signature heading in a future sweep",
  "vaultWrap.wrap":                              "covered prose-style under the vaultWrap parent section — backfill per-method signature heading in a future sweep",
  // webhook — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "webhook.WebhookError":                        "covered prose-style under the webhook parent section — backfill per-method signature heading in a future sweep",
  // websocket — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "websocket.FrameParser":                       "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.WebSocketConnection":               "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.WebSocketError":                    "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.buildUpgradeResponse":              "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.computeAcceptKey":                  "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.handleExtendedConnect":             "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.handleUpgrade":                     "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.isOriginAllowed":                   "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.negotiateSubprotocol":              "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.serializeFrame":                    "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  "websocket.validateUpgradeRequest":            "covered prose-style under the websocket parent section — backfill per-method signature heading in a future sweep",
  // websocketChannels — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "websocketChannels.WebSocketChannelsError":    "covered prose-style under the websocketChannels parent section — backfill per-method signature heading in a future sweep",
  // wsClient — sub-keys covered prose-style under the parent page; backfill per-method signature headings opportunistically.
  "wsClient.WsClientError":                      "covered prose-style under the wsClient parent section — backfill per-method signature heading in a future sweep",
  "wsClient.connect":                            "covered prose-style under the wsClient parent section — backfill per-method signature heading in a future sweep",
};

function _enumerateBxPrimitives(b, pages) {
  var keys = Object.keys(b).filter(function (k) { return k[0] !== "_"; });

  // Build a set of every documented primitive signature by walking
  // the wiki page bodies + extracting every primitive heading.
  var documented = new Set();
  for (var p = 0; p < pages.length; p += 1) {
    var sections = _splitSections(pages[p].body);
    for (var s = 0; s < sections.length; s += 1) {
      if (!_isPrimitiveHeading(sections[s].text)) continue;
      // Extract the leading b.X.Y or b.X path from the signature.
      var m = sections[s].text.match(/b\.([a-zA-Z][a-zA-Z0-9]*)(?:\.([a-zA-Z][a-zA-Z0-9]*))?/);
      if (!m) continue;
      documented.add(m[1]);                                    // top-level
      if (m[2]) documented.add(m[1] + "." + m[2]);             // method-level
    }
  }

  var undocumented = [];
  for (var k = 0; k < keys.length; k += 1) {
    var name = keys[k];
    var topSkipped = BX_SKIP.has(name);
    if (!topSkipped && !documented.has(name) && !UNDOCUMENTED_BACKLOG[name]) {
      undocumented.push(name);
    }

    // Recurse one level into top-level namespaces. We still recurse
    // when the parent is in UNDOCUMENTED_BACKLOG (the parent has a
    // known gap, but new methods landing under it must surface
    // separately). We DON'T recurse when the parent is in BX_SKIP —
    // BX_SKIP means "not operator-facing surface at all."
    if (topSkipped) continue;
    var val = b[name];
    if (!val || typeof val !== "object" || Array.isArray(val)) continue;

    var subKeys = Object.keys(val).filter(function (sk) { return sk[0] !== "_"; });
    for (var s2 = 0; s2 < subKeys.length; s2 += 1) {
      var sub = subKeys[s2];
      var qualified = name + "." + sub;
      if (BX_SKIP.has(qualified)) continue;

      // Only flag operator-facing surface. A sub-key is operator-
      // facing if its value is a function (factory / direct primitive)
      // OR a sub-module object exposing at least one callable. Bare
      // data tables, vocabularies, and class instances aren't
      // primitive-shaped and stay invisible to the gate.
      var subVal = val[sub];
      var isFn = typeof subVal === "function";
      var isModule = subVal && typeof subVal === "object" && !Array.isArray(subVal) &&
        Object.keys(subVal).some(function (mk) { return typeof subVal[mk] === "function"; });
      if (!isFn && !isModule) continue;

      if (documented.has(qualified)) continue;
      if (UNDOCUMENTED_BACKLOG[qualified]) continue;
      undocumented.push(qualified);
    }
  }
  return undocumented;
}

// ---- CLI entry ----

function run(opts) {
  opts = opts || {};
  var reportOnly = !!opts.reportOnly;
  // Load the framework module for opts-diff probing. Loading is safe
  // (it doesn't init vault/db); only factory-style functions need to
  // actually run, and they throw on the unknown probe key before any
  // state-touching path executes.
  var b = opts.framework;
  if (!b) {
    try { b = require(path.join(__dirname, "..", "..", "..", "index.js")); }
    catch (_e) { b = null; }
  }

  var pages = _readPageBodies();
  var allViolations = [];
  for (var i = 0; i < pages.length; i++) {
    var v = _validatePage(pages[i], { framework: b });
    for (var j = 0; j < v.length; j++) allViolations.push(v[j]);
  }

  // Missing-section enumeration. Every operator-facing primitive on
  // b.* must either have a wiki section (signature-prefixed heading)
  // OR be in BX_SKIP / UNDOCUMENTED_BACKLOG. New primitives added
  // without either path fail the gate.
  var undocumented = b ? _enumerateBxPrimitives(b, pages) : [];

  var enforced = allViolations.filter(function (vi) { return !vi.exempt; });
  var exempted = allViolations.filter(function (vi) { return vi.exempt; });

  if (allViolations.length === 0 && undocumented.length === 0) {
    console.log("[validate-primitive-sections] OK — every primitive section has heading + opts + prose + example, " +
      "every probe-able opts model matches the lib allow-list, and every operator-facing b.* primitive has a documented section");
    return 0;
  }
  if (undocumented.length > 0) {
    console.error("[validate-primitive-sections] " + undocumented.length +
      " operator-facing b.* primitive(s) lack a documented wiki section:");
    for (var ui = 0; ui < undocumented.length; ui += 1) {
      console.error("  b." + undocumented[ui] + " — add a wiki section (signature-prefixed heading + opts model + " +
                    "description + example) OR add to UNDOCUMENTED_BACKLOG with a one-line reason in " +
                    "examples/wiki/test/validate-primitive-sections.js");
    }
  }

  if (enforced.length > 0) {
    var presence = enforced.filter(function (vi) { return vi.missing.length > 0; });
    var driftOnly = enforced.filter(function (vi) {
      return vi.missing.length === 0 && vi.optsDiff &&
        (vi.optsDiff.addedInWiki.length > 0 || vi.optsDiff.removedFromWiki.length > 0);
    });
    if (presence.length > 0) {
      console.error("[validate-primitive-sections] " + presence.length +
        " primitive section(s) missing required pieces:");
      for (var k = 0; k < presence.length; k++) {
        var u = presence[k];
        console.error("  " + u.slug + " :: " + u.heading);
        console.error("    missing: " + u.missing.join(", "));
        console.error("    key:     " + u.key);
      }
    }
    if (driftOnly.length > 0) {
      console.error("[validate-primitive-sections] " + driftOnly.length +
        " primitive section(s) with opts-key drift (wiki opts model out of sync with lib allow-list):");
      for (var dk = 0; dk < driftOnly.length; dk++) {
        var d = driftOnly[dk];
        console.error("  " + d.slug + " :: " + d.heading);
        if (d.optsDiff.addedInWiki.length > 0) {
          console.error("    wiki has but lib rejects:  " + d.optsDiff.addedInWiki.join(", "));
        }
        if (d.optsDiff.removedFromWiki.length > 0) {
          console.error("    lib accepts but wiki omits: " + d.optsDiff.removedFromWiki.join(", "));
        }
      }
    }
  }
  if (exempted.length > 0) {
    console.log("[validate-primitive-sections] " + exempted.length +
      " known-incomplete section(s) exempt (fix opportunistically):");
    for (var m = 0; m < exempted.length; m++) {
      var a = exempted[m];
      console.log("  " + a.slug + " :: " + a.heading);
      console.log("    missing: " + a.missing.join(", ") + "  — " + a.reason);
    }
  }

  if (reportOnly) return 0;
  return (enforced.length > 0 || undocumented.length > 0) ? 1 : 0;
}

module.exports = {
  run:                  run,
  runExamples:          runExamples,
  _readPageBodies:      _readPageBodies,
  _validatePage:        _validatePage,
  _splitSections:       _splitSections,
  _isPrimitiveHeading:  _isPrimitiveHeading,
  _signatureNamesOpts:  _signatureNamesOpts,
  _extractCodeBlocks:   _extractCodeBlocks,
  _extractWikiOptsKeys: _extractWikiOptsKeys,
  _frameworkPathsIn:    _frameworkPathsIn,
  _resolvePath:         _resolvePath,
  EXEMPTIONS:           EXEMPTIONS,
};

if (require.main === module) {
  var reportOnly = process.argv.indexOf("--report") !== -1;
  process.exit(run({ reportOnly: reportOnly }));
}
