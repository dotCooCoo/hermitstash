"use strict";
// validate-nav-coverage — every nav entry in lib/nav.js must:
//
//   1. Resolve to a seeded page (groupName === slug, slug === "index")
//      whose body is non-empty.
//   2. Render through the template chain without an error.
//   3. Contain the page's <h1> title text.
//   4. Pass minimum-content gates: at least one <p> or <pre> in the
//      body so a placeholder page can't sneak through with just the
//      H1 + a "TODO" callout.
//   5. Resolve the slug back to its declared NAV group via
//      nav.groupForPath. If groupForPath returns null the nav-active
//      highlight breaks — fail.
//
// Hits the live HTTP layer too (rendered through routes/pages.js +
// b.cache.wrap + template.render) so any rendering glitch surfaces
// from the same code path operators hit. Sends the same browser-
// shaped header set as the e2e suite to clear the bot-guard / fetch-
// metadata middleware.
//
// Run standalone (assumes a wiki server is listening on the given
// port; without --port defaults to 3211 — the dev convention):
//   node examples/wiki/test/validate-nav-coverage.js
//   node examples/wiki/test/validate-nav-coverage.js --port=3008
//   node examples/wiki/test/validate-nav-coverage.js --report
//
// Wired into examples/wiki/test/e2e.js as part of the runtime pass —
// it boots the wiki app in-process via buildApp, hits the live HTTP
// listener through the same _request helper the e2e uses, and
// asserts every nav entry is reachable + rendered + populated.

var http = require("node:http");

var nav  = require("../lib/nav");
var site = require("../site.config");

var REPORT_ONLY = process.argv.indexOf("--report") !== -1;
var PORT_ARG = process.argv.find(function (a) { return a.indexOf("--port=") === 0; });
var PORT = PORT_ARG ? parseInt(PORT_ARG.split("=")[1], 10) : 3211;
var HOST = "127.0.0.1";

var BROWSER_HEADERS = {
  "user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "identity",
  "sec-fetch-dest":  "document",
  "sec-fetch-mode":  "navigate",
  "sec-fetch-site":  "none",
};

function _get(reqPath) {
  return new Promise(function (resolve, reject) {
    var req = http.request({
      host: HOST, port: PORT, method: "GET",
      path: reqPath, headers: BROWSER_HEADERS,
    }, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    req.setTimeout(5000, function () { req.destroy(new Error("nav-coverage: request timed out")); });
    req.end();
  });
}

// Body-level gates that catch placeholder pages: every nav entry must
// have at least one prose paragraph + (a heading OR a code block).
// Pages that legitimately have no headings (landing-only pages with
// big card grids) opt in via .card-grid.
function _checkBody(html, expectedTitle) {
  var issues = [];
  if (!html || html.length < 200) {
    issues.push("response body too short (" + (html ? html.length : 0) + " bytes) — page exists but is empty");
    return issues;
  }
  if (html.indexOf("<main") === -1 || html.indexOf("</main>") === -1) {
    issues.push("response missing <main> wrapper");
    return issues;
  }
  var mainStart = html.indexOf("<main");
  var mainEnd   = html.indexOf("</main>");
  var main = html.slice(mainStart, mainEnd);

  // H1 with the expected title text — server-side title resolved from
  // the page record's `title` column. Hand-authored bodies start with
  // <h1>...</h1>; generated bodies do too.
  var h1Match = main.match(/<h1[^>]*>([\s\S]*?)<\/h1>/);
  if (!h1Match) {
    issues.push("missing <h1> in <main>");
  } else {
    var h1Text = h1Match[1]
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
    if (h1Text !== expectedTitle && h1Text.indexOf(expectedTitle) === -1) {
      issues.push("<h1> text `" + h1Text + "` does not contain expected title `" + expectedTitle + "`");
    }
  }

  // Min content: at least one <p> AND (one <pre>, one <h2>, one <h3>,
  // or one .card-grid). Pure-prose pages still need at least one
  // sub-heading or code block to count as "populated".
  var paraCount  = (main.match(/<p[\s>]/g) || []).length;
  var preCount   = (main.match(/<pre[\s>]/g) || []).length;
  var h2Count    = (main.match(/<h2[\s>]/g) || []).length;
  var h3Count    = (main.match(/<h3[\s>]/g) || []).length;
  var hasCards   = main.indexOf("card-grid") !== -1;
  if (paraCount === 0) {
    issues.push("no <p> paragraphs in <main> — page has no prose body");
  }
  if (preCount === 0 && h2Count === 0 && h3Count === 0 && !hasCards) {
    issues.push("page has no <h2>/<h3>/<pre>/.card-grid — looks like a placeholder/empty page");
  }
  return issues;
}

async function validate() {
  var findings = [];
  var checked = 0;

  // Walk EVERY non-hidden entry in site.config.js — the validator's
  // job is to confirm every nav entry resolves to a populated page.
  // Group-less entries (e.g. landing-page-only links) are still
  // checked; they just don't carry a group highlight.
  var entries = site.ENTRIES
    .filter(function (e) { return !e.hidden; })
    .map(function (e) {
      return { slug: e.slug, title: e.title, group: e.group || null };
    });

  for (var i = 0; i < entries.length; i++) {
    var entry = entries[i];
    var url = "/" + entry.slug;
    checked++;

    var res;
    try { res = await _get(url); }
    catch (e) {
      findings.push({ kind: "request-error", slug: entry.slug, group: entry.group, msg: "request failed: " + (e && e.message) });
      continue;
    }

    if (res.statusCode !== 200) {
      findings.push({
        kind: "status", slug: entry.slug, group: entry.group,
        msg: "GET " + url + " -> " + res.statusCode + " (expected 200)",
      });
      continue;
    }
    if (!/text\/html/.test(res.headers["content-type"] || "")) {
      findings.push({
        kind: "content-type", slug: entry.slug, group: entry.group,
        msg: "Content-Type " + res.headers["content-type"] + " (expected text/html)",
      });
      continue;
    }

    var bodyIssues = _checkBody(res.body, entry.title);
    bodyIssues.forEach(function (msg) {
      findings.push({ kind: "body-content", slug: entry.slug, group: entry.group, msg: msg });
    });

    // groupForPath round-trip — every navigable slug must resolve back
    // to its declared group so the sidebar opens the correct
    // <details> on page load.
    if (entry.group) {
      var resolved = nav.groupForPath(url);
      if (resolved !== entry.group) {
        findings.push({
          kind: "group-resolve", slug: entry.slug, group: entry.group,
          msg: "groupForPath('" + url + "') -> " + JSON.stringify(resolved) + " (expected `" + entry.group + "`)",
        });
      }
    }
  }

  return { checked: checked, findings: findings };
}

function _report(result) {
  if (result.findings.length === 0) {
    console.log("[validate-nav-coverage] OK - " + result.checked + " nav entries reachable + populated");
    return 0;
  }
  console.log("[validate-nav-coverage] " + result.findings.length + " finding(s) across " + result.checked + " nav entries:");
  result.findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] /" + f.slug + (f.group ? " (group: " + f.group + ")" : ""));
    console.log("     " + f.msg);
  });
  return REPORT_ONLY ? 0 : 1;
}

if (require.main === module) {
  validate().then(function (result) { process.exit(_report(result)); }).catch(function (e) {
    console.error("[validate-nav-coverage] crashed:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { validate: validate };
