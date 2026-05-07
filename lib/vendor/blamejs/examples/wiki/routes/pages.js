"use strict";
// Public page routes — landing, group/page lookups, search.
// Uses b.cache for rendered-HTML cache, b.render.html for SSR,
// b.template (mounted by createApp), and b.db.prepare for lookups.

var b = require("@blamejs/core");
var nav = require("../lib/nav");

// Layout-data shape shared by both the per-request render path and the
// cacheable render path. The cspNonce field is the only thing that
// differs: live paths get the real nonce, cacheable paths get the
// framework's stable placeholder (substituted at serve time via
// b.middleware.cspNonce's substitute helper).
var DEFAULT_DESCRIPTION =
  "blamejs — the Node framework that owns its stack. Post-quantum crypto, " +
  "audit chain, sealed storage, zero npm dependencies.";

function _layoutData(req, ctx, nonce) {
  var siteUrl = (ctx && ctx.siteUrl) || "https://blamejs.com";
  var pathname = (req.url || "/").split("?")[0];
  return {
    cspNonce:    nonce,
    locale:      req.locale || "en",
    dir:         req.dir ? req.dir() : "ltr",
    user:        req.user || null,
    csrfToken:   req.csrfToken || "",
    searchQuery: "",
    title:       "",
    assets:      (ctx && ctx.assets) || {},
    siteUrl:     siteUrl,
    canonical:   siteUrl + pathname,
    description: DEFAULT_DESCRIPTION,
    ogImage:     siteUrl + "/img/blamejs-logo.png",
    ogType:      "website",
    // Sidebar nav: data-driven via NAV_GROUPS so the partial renders
    // a {% for %} loop with <details open> on the section containing
    // the current page. groupForPath returns null for routes outside
    // the wiki nav (admin, login, etc.) — every section starts
    // collapsed in that case.
    nav:          nav.NAV_GROUPS,
    currentGroup: nav.groupForPath(pathname),
    currentPath:  pathname,
  };
}
function _layoutDataLive(req, ctx) {
  return _layoutData(req, ctx, req.cspNonce || (req.res && req.res.locals && req.res.locals.cspNonce) || "");
}
function _layoutDataForCache(req, ctx) {
  return _layoutData(req, ctx, ctx.nonceMw.PLACEHOLDER);
}

// Pull a meta-description from a page body — the first <p>..</p>'s
// text, tags stripped, normalised whitespace, capped at 160 chars
// (the Google SERP truncation point). Falls back to the site default
// when the body has no <p>.
function _synthDescription(body, fallback) {
  if (typeof body !== "string") return fallback;
  var m = body.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
  if (!m) return fallback;
  var text = m[1].replace(/<[^>]+>/g, "").replace(/&[a-z0-9#]+;/gi, " ").replace(/\s+/g, " ").trim();
  if (!text) return fallback;
  var maxLen = b.constants.BYTES.bytes(160);
  if (text.length > maxLen) text = text.slice(0, maxLen - 3).trimEnd() + "...";
  return text;
}

// Specific routes (literal paths, registered FIRST so they match before
// the /:group catch-all). The catch-all `/:group` would otherwise
// intercept /login, /admin, /logout, etc. — operator-supplied paths
// must register between the specifics and the catch-all.
function registerSpecific(router, ctx) {
  var db = ctx.db;
  var template = ctx.template;

  // ---- Landing ----
  router.get("/", function (req, res) {
    var data = Object.assign(_layoutDataLive(req, ctx), {
      title: "blamejs",
    });
    var html = template.render("home", data);
    b.render.htmlString(res, html);
  });

  // /healthz / /readyz / /startupz are handled by b.middleware.health
  // mounted at the top of the chain; no route registered here.

  // ---- robots.txt ----
  router.get("/robots.txt", function (req, res) {
    var siteUrl = ctx.siteUrl || "https://blamejs.com";
    var body =
      "User-agent: *\n" +
      "Allow: /\n" +
      "Disallow: /admin\n" +
      "Disallow: /admin/\n" +
      "Disallow: /login\n" +
      "Disallow: /logout\n" +
      "\n" +
      "Sitemap: " + siteUrl + "/sitemap.xml\n";
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(body);
  });

  // ---- sitemap.xml ----
  router.get("/sitemap.xml", function (req, res) {
    var siteUrl = ctx.siteUrl || "https://blamejs.com";
    var rows = db.prepare(
      "SELECT groupName, slug, updatedAt FROM pages ORDER BY groupName, slug"
    ).all();
    var lines = [];
    lines.push('<?xml version="1.0" encoding="UTF-8"?>');
    lines.push('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">');
    // Home page
    var homeMod = (rows[0] && rows[0].updatedAt)
      ? new Date(rows[0].updatedAt).toISOString().slice(0, 10)
      : new Date().toISOString().slice(0, 10);
    lines.push("  <url>");
    lines.push("    <loc>" + siteUrl + "/</loc>");
    lines.push("    <lastmod>" + homeMod + "</lastmod>");
    lines.push("    <changefreq>weekly</changefreq>");
    lines.push("    <priority>1.0</priority>");
    lines.push("  </url>");
    rows.forEach(function (r) {
      // Each group's index is served at /<group>; non-index pages at /<group>/<slug>.
      var loc = r.slug === "index"
        ? siteUrl + "/" + r.groupName
        : siteUrl + "/" + r.groupName + "/" + r.slug;
      var mod = new Date(r.updatedAt).toISOString().slice(0, 10);
      lines.push("  <url>");
      lines.push("    <loc>" + loc + "</loc>");
      lines.push("    <lastmod>" + mod + "</lastmod>");
      lines.push("    <changefreq>weekly</changefreq>");
      lines.push("    <priority>0.8</priority>");
      lines.push("  </url>");
    });
    lines.push("</urlset>");
    res.setHeader("Content-Type", "application/xml; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.end(lines.join("\n"));
  });

  // ---- Search (FTS5 — operator-side recipe) ----
  router.get("/search", async function (req, res) {
    // req.url is a path-relative form (`/search?q=…`); safeUrl.parse
    // requires an absolute URL, so synthesize a localhost origin before
    // parsing. The host is discarded — only the query string matters.
    var url = b.safeUrl.parse("http://localhost" + req.url, {
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    });
    var q = (url.searchParams.get("q") || "").trim();
    var hits = [];
    if (q.length > 0 && q.length < 200) {
      try {
        // FTS5 MATCH; snippet() builds a contextual excerpt around hits.
        // Operator-supplied query is bound via parameter; FTS5 escapes
        // its own MATCH grammar, but we still cap length to bound work.
        hits = db.prepare(
          "SELECT groupName, slug, title, snippet(pages_fts, 3, '<mark>', '</mark>', '…', 16) AS snippet " +
          "FROM pages_fts WHERE pages_fts MATCH ? LIMIT 50"
        ).all(q);
      } catch (_e) {
        // FTS5 throws on malformed MATCH expressions (operator typed
        // raw operators). Fall back to empty hits — user-friendly.
        hits = [];
      }
    }
    var data = Object.assign(_layoutDataLive(req, ctx), {
      title:       "Search",
      searchQuery: q,
      hits:        hits,
    });
    var html = template.render("search", data);
    b.render.htmlString(res, html);
  });
}

// Catch-all routes (parameterized paths). Register LAST after every
// specific path is in place; the router matches in registration order.
function registerCatchAll(router, ctx) {
  var pageCache = ctx.pageCache;
  var db = ctx.db;
  var template = ctx.template;

  // ---- Group/page lookup ----
  // Convention: each group has a landing page stored at slug "index".
  // /<group>          serves the group's index directly (no redirect).
  // /<group>/<slug>   serves the named page within the group.
  // /<group>/index    301-redirects to /<group> so there's one canonical URL.
  async function _renderPage(req, res, group, slug) {
    var cacheKey = group + "/" + slug;
    var html = await pageCache.wrap(cacheKey, async function () {
      var row = db.prepare(
        "SELECT groupName, slug, title, body, updatedAt, updatedBy " +
        "FROM pages WHERE groupName = ? AND slug = ?"
      ).get(group, slug);
      if (!row) return null;
      var base = _layoutDataForCache(req, ctx);
      var data = Object.assign(base, {
        title:        row.title,
        groupName:    row.groupName,
        slug:         row.slug,
        body:         row.body,
        updatedAtIso: new Date(row.updatedAt).toISOString(),
        updatedBy:    row.updatedBy || "unknown",
        description:  _synthDescription(row.body, base.description),
        ogType:       "article",
      });
      return template.render("page", data);
    });
    if (!html) {
      return b.render.htmlString(res, "<h1>Not found</h1><p>No such page.</p>", { status: 404 });
    }
    b.render.htmlString(res, ctx.nonceMw.substitute(html, req));
  }

  router.get("/:group", async function (req, res) {
    var group = req.params.group;
    if (!/^[a-z0-9-]+$/.test(group)) {
      return b.render.htmlString(res, "Not found", { status: 404 });
    }
    return _renderPage(req, res, group, "index");
  });

  router.get("/:group/:slug", async function (req, res) {
    var group = req.params.group;
    var slug = req.params.slug;
    if (!/^[a-z0-9-]+$/.test(group) || !/^[a-z0-9-]+$/.test(slug)) {
      return b.render.htmlString(res, "Not found", { status: 404 });
    }
    // Canonicalize: /<group>/index permanently redirects to /<group>.
    if (slug === "index") {
      return b.render.redirect(res, "/" + group, { status: 301 });
    }
    return _renderPage(req, res, group, slug);
  });
}

module.exports = {
  registerSpecific: registerSpecific,
  registerCatchAll: registerCatchAll,
};
