"use strict";
// Wiki navigation structure — single source of truth for the sidebar
// + the per-page "current section" highlight. Both routes/pages.js and
// routes/admin.js feed this into _layoutData so the nav partial can
// render data-driven {% for %} loops with the right <details open>
// flag on the section containing the current page.

var NAV_GROUPS = [
  { name: "Data", items: [
    { slug: "database",        title: "Database" },
    { slug: "object-store",    title: "Object Store" },
    { slug: "queue-cache",     title: "Queue & Cache" },
  ] },
  { name: "Identity", items: [
    { slug: "auth",            title: "Authentication" },
    { slug: "access-control",  title: "Access Control" },
  ] },
  { name: "Crypto", items: [
    { slug: "crypto-vault",    title: "Crypto & Vault" },
    { slug: "network-crypto",  title: "Network Crypto" },
  ] },
  { name: "HTTP", items: [
    { slug: "routing",         title: "Routing" },
    { slug: "middleware",      title: "Middleware" },
    { slug: "outbound-http",   title: "Outbound HTTP" },
    { slug: "network-config",  title: "Network Configurability" },
  ] },
  { name: "Validation", items: [
    { slug: "safe-parsers",    title: "Safe Parsers" },
  ] },
  { name: "Communication", items: [
    { slug: "websockets",      title: "WebSockets" },
    { slug: "mail",            title: "Mail" },
    { slug: "notifications",   title: "Notifications" },
  ] },
  { name: "Tools", items: [
    { slug: "observability",   title: "Observability" },
    { slug: "testing",         title: "Testing" },
    { slug: "i18n-locale",     title: "i18n & Locale" },
    { slug: "format-helpers",  title: "Format Helpers" },
  ] },
  { name: "Compliance", items: [
    { slug: "compliance-patterns", title: "Compliance Patterns" },
  ] },
  { name: "Production", items: [
    { slug: "cluster",         title: "Cluster Mode" },
    { slug: "reliability",     title: "Reliability" },
    { slug: "backup-restore",  title: "Backup & Restore" },
  ] },
];

// Resolve a request pathname to the nav group containing it.
// Returns null when the path doesn't match any nav item (the welcome
// page, admin area, etc. — those routes get no group highlight).
function groupForPath(pathname) {
  if (typeof pathname !== "string") return null;
  // Strip leading slash + trailing slash + query string
  var clean = pathname.replace(/^\/+/, "").replace(/\/+$/, "").split("?")[0];
  // Match by primary segment (the slug). Wiki pages live at /<slug>;
  // category landing pages are also at /<slug> (the catch-all route
  // serves both).
  var slug = clean.split("/")[0];
  if (!slug) return null;
  for (var i = 0; i < NAV_GROUPS.length; i++) {
    for (var j = 0; j < NAV_GROUPS[i].items.length; j++) {
      if (NAV_GROUPS[i].items[j].slug === slug) return NAV_GROUPS[i].name;
    }
  }
  return null;
}

module.exports = {
  NAV_GROUPS:    NAV_GROUPS,
  groupForPath:  groupForPath,
};
