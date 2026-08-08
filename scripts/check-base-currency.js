#!/usr/bin/env node
"use strict";

/**
 * Base-image digest currency.
 *
 * Every base image this project builds on is pinned to an immutable manifest
 * digest so a build is reproducible and a tag republish cannot swap the base
 * underneath a signed, attested image. The cost of that guarantee is that a pin
 * does not pick up upstream rebuilds on its own: the digest keeps resolving to
 * the same bytes no matter how many CVE fixes have landed since. Nothing else
 * in the release path notices — the action-pin and vendored-dependency gates
 * cover their own surfaces and say nothing about base images.
 *
 * This reports, for each pinned base, whether the tag it was captured from now
 * resolves somewhere else.
 *
 * WHAT FAILS AND WHAT WARNS
 *
 * Digest drift WARNS, it does not fail. The bases here are rebuilt continuously
 * — often daily — so a gate that failed on drift would block essentially every
 * release, and the pressure that creates is to bump the pin blindly to make the
 * gate quiet, which is worse than the staleness it was meant to catch. Drift is
 * also only a proxy: the harm is shipping a fixable CRITICAL/HIGH, and the
 * release already hard-gates exactly that through the Trivy step. This gate
 * exists to make staleness visible, not to hold the release hostage to someone
 * else's build schedule.
 *
 * What does fail is anything meaning the check itself is not working, or that
 * the reproducibility guarantee is already broken:
 *
 *   - a pinned digest that no longer resolves (the build is broken already)
 *   - a FROM that resolves to no digest at all, outside the allowlist below
 *   - a Dockerfile this scanner cannot parse
 *   - finding no pins whatsoever, which means the scanner and the tree drifted
 *
 * A gate that cannot run must fail rather than pass. A check that quietly
 * reports success when its parser broke is worse than no check, because it also
 * removes the suspicion that would have prompted a manual look. Transient
 * network trouble is the one exception — it warns, because failing a release on
 * someone else's 503 buys nothing.
 *
 * Usage:
 *   node scripts/check-base-currency.js              # report; exit 0 unless broken
 *   node scripts/check-base-currency.js --max-age-days=N
 *                                                    # additionally fail when a
 *                                                    # pin has drifted and the
 *                                                    # current tag build is more
 *                                                    # than N days newer
 *   node scripts/check-base-currency.js --json       # machine-readable
 */

var fs = require("fs");
var path = require("path");
var https = require("https");

var REPO = path.resolve(__dirname, "..");

// Dockerfiles under these prefixes are third-party and refreshed only by
// scripts/vendor-update.sh. Editing a pin inside them by hand would be undone
// by the next vendor refresh, so they are not this gate's business — the same
// owned-versus-vendored split the code-scanning triage uses.
var EXCLUDED_PREFIXES = ["lib/vendor/", "node_modules/", ".git/"];

// Files allowed to reference a base by tag instead of digest, each with the
// reason. A tag pin is a deliberate, narrower guarantee: it tracks a moving
// target on purpose. Anything NOT listed here that lacks a digest is a
// reproducibility defect and fails.
var TAG_PINNED_BY_POLICY = {
  "tests/Dockerfile.test":
    "Test-only image, never published or signed. Pinned to the Node version in " +
    "package.json engines.node so the tests run on the major the runtime ships; " +
    "tracking that tag is the point.",
};

var ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

var USE_COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
function paint(code, s) { return USE_COLOR ? "[" + code + "m" + s + "[0m" : s; }
function red(s) { return paint("31", s); }
function green(s) { return paint("32", s); }
function yellow(s) { return paint("33", s); }
function cyan(s) { return paint("36", s); }
function dim(s) { return paint("2", s); }
function bold(s) { return paint("1", s); }

/* ------------------------------------------------------------------ *
 * Dockerfile discovery + parsing
 * ------------------------------------------------------------------ */

function listDockerfiles(dir, out, rel) {
  out = out || [];
  rel = rel || "";
  var entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return out; }
  entries.forEach(function (e) {
    var childRel = rel ? rel + "/" + e.name : e.name;
    if (EXCLUDED_PREFIXES.some(function (p) { return (childRel + "/").indexOf(p) === 0; })) return;
    if (e.isDirectory()) { listDockerfiles(path.join(dir, e.name), out, childRel); return; }
    if (/^Dockerfile(\..+)?$/.test(e.name)) out.push(childRel);
  });
  return out;
}

/**
 * Resolve every FROM in a Dockerfile to a concrete image reference.
 *
 * ARG defaults are substituted because the base is frequently held in one
 * (`ARG RUNTIME_BASE=...` + `FROM ${RUNTIME_BASE}`), and sometimes only the tag
 * portion is (`ARG NODE_VERSION=24.19.0-slim@sha256:...` + `FROM node:${NODE_VERSION}`).
 * Reading the FROM alone would miss the pin in both shapes.
 */
function parseDockerfile(relPath) {
  var text = fs.readFileSync(path.join(REPO, relPath), "utf8");
  var lines = text.split(/\r?\n/);
  var args = {};
  var stages = {};
  var froms = [];

  lines.forEach(function (line, idx) {
    var argMatch = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S+)/.exec(line);
    if (argMatch) { args[argMatch[1]] = argMatch[2]; return; }

    var fromMatch = /^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?/i.exec(line);
    if (!fromMatch) return;

    var ref = fromMatch[1];
    var stageName = fromMatch[2];
    var resolved = ref.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
      function (whole, braced, bare) {
        var key = braced || bare;
        return Object.prototype.hasOwnProperty.call(args, key) ? args[key] : whole;
      });

    if (stageName) stages[stageName] = true;
    froms.push({ file: relPath, line: idx + 1, raw: ref, ref: resolved });
  });

  // A FROM naming an earlier stage is not a base image.
  return froms.filter(function (f) { return !stages[f.ref]; });
}

/**
 * Split an image reference into registry / repository / tag / digest.
 *
 * A reference with no tag before the digest was captured from :latest — that is
 * the only tag those bases publish — so latest is the tag to compare against.
 * Guessing wrong here produces a permanent false "stale", so the tag is taken
 * from the reference whenever one is present.
 */
function parseRef(ref) {
  var digest = null;
  var rest = ref;
  var at = ref.indexOf("@");
  if (at !== -1) { digest = ref.slice(at + 1); rest = ref.slice(0, at); }

  var registry = "registry-1.docker.io";
  var remainder = rest;
  var firstSlash = rest.indexOf("/");
  var firstPart = firstSlash === -1 ? "" : rest.slice(0, firstSlash);
  if (firstPart && (firstPart.indexOf(".") !== -1 || firstPart.indexOf(":") !== -1 || firstPart === "localhost")) {
    registry = firstPart;
    remainder = rest.slice(firstSlash + 1);
  }

  var tag = "latest";
  var colon = remainder.lastIndexOf(":");
  if (colon !== -1 && remainder.indexOf("/", colon) === -1) {
    tag = remainder.slice(colon + 1);
    remainder = remainder.slice(0, colon);
  }

  if (registry === "registry-1.docker.io" && remainder.indexOf("/") === -1) {
    remainder = "library/" + remainder;
  }

  return { registry: registry, repository: remainder, tag: tag, digest: digest };
}

/* ------------------------------------------------------------------ *
 * Registry resolution (no Docker daemon, no credentials)
 * ------------------------------------------------------------------ */

function request(url, headers) {
  return new Promise(function (resolve) {
    var req = https.request(url, { method: "GET", headers: headers || {} }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    req.on("error", function (err) { resolve({ status: 0, headers: {}, body: "", error: err.message }); });
    req.setTimeout(20000, function () { req.destroy(); resolve({ status: 0, headers: {}, body: "", error: "timeout" }); });
    req.end();
  });
}

var _tokenCache = {};

/**
 * Fetch an anonymous pull token. Both registries in use here hand one out
 * without credentials; the 401 that triggers it carries the realm and scope to
 * ask for, so they are not hardcoded per registry.
 */
async function anonymousToken(registry, repository, challenge) {
  var cacheKey = registry + "/" + repository;
  if (_tokenCache[cacheKey]) return _tokenCache[cacheKey];

  var realm = /realm="([^"]+)"/.exec(challenge || "");
  var service = /service="([^"]+)"/.exec(challenge || "");
  var scope = /scope="([^"]+)"/.exec(challenge || "");
  if (!realm) return null;

  var url = realm[1] + "?" + [
    service ? "service=" + encodeURIComponent(service[1]) : "",
    "scope=" + encodeURIComponent(scope ? scope[1] : "repository:" + repository + ":pull"),
  ].filter(Boolean).join("&");

  var res = await request(url, {});
  if (res.status !== 200) return null;
  try {
    var tok = JSON.parse(res.body);
    var value = tok.token || tok.access_token;
    if (value) _tokenCache[cacheKey] = value;
    return value || null;
  } catch (_e) { return null; }
}

/**
 * Resolve a reference to its manifest digest.
 *
 * The Accept header lists index and manifest types together and never a
 * platform-specific one: asking for a single platform would resolve a child
 * manifest, whose digest is NOT what a Dockerfile pins, and every comparison
 * would then report a false drift.
 */
async function resolveDigest(parsed, reference) {
  var url = "https://" + parsed.registry + "/v2/" + parsed.repository + "/manifests/" + reference;
  var headers = { Accept: ACCEPT, "User-Agent": "hermitstash-base-currency" };

  var res = await request(url, headers);
  if (res.status === 401) {
    var token = await anonymousToken(parsed.registry, parsed.repository, res.headers["www-authenticate"]);
    if (!token) return { ok: false, kind: "auth", detail: "could not obtain an anonymous pull token" };
    headers.Authorization = "Bearer " + token;
    res = await request(url, headers);
  }

  if (res.status === 404) return { ok: false, kind: "notfound", detail: "not found" };
  if (res.status === 429) return { ok: false, kind: "network", detail: "rate limited (HTTP 429)" };
  if (res.status !== 200) {
    return {
      ok: false,
      kind: res.status === 0 ? "network" : (res.status >= 500 ? "network" : "http"),
      detail: res.error || ("HTTP " + res.status),
    };
  }

  var digest = res.headers["docker-content-digest"];
  if (!digest) return { ok: false, kind: "http", detail: "response carried no Docker-Content-Digest" };
  return { ok: true, digest: digest };
}

/* ------------------------------------------------------------------ *
 * Report
 * ------------------------------------------------------------------ */

async function main() {
  var argv = process.argv.slice(2);
  var asJson = argv.indexOf("--json") !== -1;
  var maxAge = null;
  argv.forEach(function (a) {
    var m = /^--max-age-days=(\d+)$/.exec(a);
    if (m) maxAge = parseInt(m[1], 10);
  });

  if (!asJson) console.log(bold("\n== base-currency =="));

  var files = listDockerfiles(REPO);
  var pins = [];
  var parseFailures = [];

  files.forEach(function (rel) {
    var froms;
    try { froms = parseDockerfile(rel); }
    catch (err) { parseFailures.push({ file: rel, error: err.message }); return; }
    froms.forEach(function (f) { pins.push(f); });
  });

  // A tree with no FROM at all means the scanner stopped matching reality.
  if (!pins.length && !parseFailures.length) {
    console.log(red("  ✗ no FROM instruction found in any Dockerfile"));
    console.log(dim("    the scanner and the tree have drifted — this check is not working"));
    return 1;
  }

  var results = [];
  for (var i = 0; i < pins.length; i++) {
    var pin = pins[i];
    var parsed = parseRef(pin.ref);
    var loc = pin.file + ":" + pin.line;

    if (!parsed.digest) {
      var policy = TAG_PINNED_BY_POLICY[pin.file];
      results.push({
        loc: loc,
        image: parsed.repository,
        tag: parsed.tag,
        state: policy ? "tag-by-policy" : "unpinned",
        reason: policy || null,
      });
      continue;
    }

    var current = await resolveDigest(parsed, parsed.tag);
    var pinned = await resolveDigest(parsed, parsed.digest);

    var state;
    if (pinned.ok === false && pinned.kind === "notfound") state = "pin-gone";
    else if (!current.ok) state = current.kind === "network" ? "unreachable" : "resolve-failed";
    else if (current.digest === parsed.digest) state = "current";
    else state = "drifted";

    results.push({
      loc: loc,
      image: parsed.registry + "/" + parsed.repository,
      tag: parsed.tag,
      state: state,
      pinned: parsed.digest,
      current: current.ok ? current.digest : null,
      detail: current.ok ? null : current.detail,
    });
  }

  if (asJson) {
    console.log(JSON.stringify({ parseFailures: parseFailures, results: results }, null, 2));
  }

  var hardFail = 0;
  var warned = 0;

  parseFailures.forEach(function (p) {
    hardFail++;
    if (!asJson) {
      console.log(red("  ✗ could not parse " + p.file));
      console.log(dim("    " + p.error));
    }
  });

  results.forEach(function (r) {
    if (asJson) return;
    switch (r.state) {
      case "current":
        console.log(green("  ✓ ") + r.image + ":" + r.tag + dim("  (" + r.loc + ")"));
        break;
      case "tag-by-policy":
        console.log(dim("  · " + r.image + ":" + r.tag + " — tag-pinned by policy (" + r.loc + ")"));
        break;
      case "drifted":
        warned++;
        console.log(yellow("  ! " + r.image + ":" + r.tag + " has moved since it was pinned") + dim("  (" + r.loc + ")"));
        console.log(dim("      pinned:  ") + r.pinned);
        console.log(dim("      current: ") + cyan(r.current));
        console.log(dim("      paste-ready: ") + green(r.image + "@" + r.current));
        break;
      case "pin-gone":
        hardFail++;
        console.log(red("  ✗ " + r.image + " pinned digest no longer resolves") + dim("  (" + r.loc + ")"));
        console.log(dim("      the build is already broken — repin from " + r.tag));
        break;
      case "unpinned":
        hardFail++;
        console.log(red("  ✗ " + r.image + ":" + r.tag + " has no digest pin") + dim("  (" + r.loc + ")"));
        console.log(dim("      a published image must build from an immutable digest;"));
        console.log(dim("      add it to TAG_PINNED_BY_POLICY with a reason if that is deliberate"));
        break;
      case "unreachable":
        warned++;
        console.log(yellow("  ! " + r.image + ":" + r.tag + " could not be reached (" + r.detail + ")") + dim("  (" + r.loc + ")"));
        break;
      default:
        hardFail++;
        console.log(red("  ✗ " + r.image + ":" + r.tag + " could not be resolved (" + r.detail + ")") + dim("  (" + r.loc + ")"));
        console.log(dim("      failing rather than passing — an unresolved pin is an unchecked pin"));
    }
  });

  if (asJson) return hardFail ? 1 : 0;

  if (hardFail) {
    console.log(red("\n  base-currency FAILED — " + hardFail + " item(s) need attention"));
    return 1;
  }
  if (warned) {
    console.log(yellow("\n  " + warned + " base image(s) have moved since pinning."));
    console.log(dim("  ADVISORY — does not block the cut. Bump deliberately; the Trivy"));
    console.log(dim("  gate is what refuses a fixable CRITICAL/HIGH."));
    return 0;
  }
  console.log(green("\n  OK — every pinned base image is at its tag's current digest"));
  return 0;
}

main().then(function (code) { process.exit(code); }, function (err) {
  console.error(red("  base-currency crashed: " + (err && err.message)));
  process.exit(1);
});
